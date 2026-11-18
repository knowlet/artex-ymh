package skillknowledge

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	"github.com/Autumn-27/norma/skill"
)

func fixture() *skill.Registry {
	return skill.NewRegistry(
		skill.Skill{Name: "sql-testing", Description: "SQL injection 查詢注入", Instructions: "# SQL injection\nUse parameterized queries.\n## Evidence\nCompare baseline and observed SQL responses."},
		skill.Skill{Name: "access-review", Description: "存取權限與授權驗證", Instructions: "# 權限驗證\n比較不同角色的存取權限，保存觀察結果。"},
	)
}

func TestSearchRelevanceAndChinese(t *testing.T) {
	idx := New(fixture())
	for query, want := range map[string]string{"SQL injection": "sql-testing", "權限驗證": "access-review"} {
		result, err := idx.Search(t.Context(), query, "", 3)
		if err != nil || len(result.Hits) == 0 || result.Hits[0].Skill != want {
			t.Fatalf("%s: %+v %v", query, result, err)
		}
		if result.Mode != "offline-lexical" || result.Hits[0].Score <= 0 {
			t.Fatal(result)
		}
		again, _ := idx.Search(t.Context(), query, "", 3)
		if !reflect.DeepEqual(result, again) {
			t.Fatal("nondeterministic ranking")
		}
	}
	for _, category := range []string{"access-review", "hidden-skill"} {
		result, err := idx.Search(t.Context(), "SQL", category, 5)
		if err != nil || len(result.Hits) != 0 {
			t.Fatalf("category leaked: %+v %v", result, err)
		}
	}
	result, err := idx.Search(t.Context(), "nonexistentuniqueterm", "", 5)
	if err != nil || len(result.Hits) != 0 || result.Hits == nil {
		t.Fatal(result, err)
	}
}

func TestSearchBoundsCancellationAndSnapshot(t *testing.T) {
	reg := fixture()
	idx := New(reg)
	reg.Add(skill.Skill{Name: "later-hidden", Instructions: "lateruniquemarker"})
	result, _ := idx.Search(t.Context(), "lateruniquemarker", "", 0)
	if len(result.Hits) != 0 {
		t.Fatal("registry mutation changed existing snapshot")
	}
	for _, q := range []string{"", " --- ", strings.Repeat("a", MaxQueryRunes+1), string([]byte{0xff})} {
		if _, err := idx.Search(t.Context(), q, "", 1); err == nil {
			t.Fatalf("accepted invalid query %q", q)
		}
	}
	if _, err := idx.Search(t.Context(), "SQL", "", -1); err == nil {
		t.Fatal("negative limit accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := New(nil).Search(ctx, "SQL", "", 0); err != context.Canceled {
		t.Fatalf("cancellation lost: %v", err)
	}
	large := skill.NewRegistry()
	for i := 0; i < 30; i++ {
		large.Add(skill.Skill{Name: fmt.Sprintf("skill-%02d", i), Instructions: strings.Repeat("權限 review ", 300)})
	}
	bounded, err := New(large).Search(t.Context(), "review", "", 100000)
	if err != nil || len(bounded.Hits) != MaxLimit {
		t.Fatalf("unbounded results: %d %v", len(bounded.Hits), err)
	}
	for _, h := range bounded.Hits {
		if !utf8.ValidString(h.Excerpt) || utf8.RuneCountInString(h.Excerpt) > MaxExcerptRunes {
			t.Fatal("invalid excerpt")
		}
	}
	oversized := New(skill.NewRegistry(skill.Skill{Name: "large", Instructions: strings.Repeat("z", maxSkillRunes+1)}))
	if !oversized.truncated {
		t.Fatal("truncated index must be disclosed")
	}
}

func TestKnowledgeToolsDoNotInvokeOrUnlock(t *testing.T) {
	reg := fixture()
	invoked := 0
	reg.OnInvoke = func(skill.Skill) string { invoked++; return "unlock" }
	tools := Tools(reg)
	for _, tool := range tools {
		in := json.RawMessage(`{}`)
		if tool.Name() == "search_knowledge" {
			in = json.RawMessage(`{"query":"SQL"}`)
		}
		result, err := tool.Call(t.Context(), in, nil)
		if err != nil || result.IsError || len(result.Extra) != 0 || invoked != 0 {
			t.Fatalf("unexpected invocation: %+v %v", result, err)
		}
		if !tool.IsReadOnly(in) || !tool.IsConcurrencySafe(in) {
			t.Fatal("retrieval must stay read-only")
		}
		if !json.Valid([]byte(result.Flatten())) {
			t.Fatal("invalid structured output")
		}
	}
	search := tools[0]
	for _, in := range []string{`null`, `[]`, `{}`, `{"query":42}`, `{"query":"SQL","unknown":true}`, `{"query":"SQL"} {}`, `{"query":"SQL","top_k":-1}`} {
		result, err := search.Call(t.Context(), json.RawMessage(in), nil)
		if err == nil && !result.IsError {
			t.Fatalf("invalid input accepted: %s", in)
		}
	}
	// Immutable search tools can be called concurrently without touching a skill
	// invocation hook or retaining a mutable registry/permission handle.
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Go(func() {
			result, err := search.Call(t.Context(), json.RawMessage(`{"query":"SQL"}`), nil)
			if err != nil || result.IsError {
				t.Error(err, result)
			}
		})
	}
	wg.Wait()
	if invoked != 0 {
		t.Fatal("search unlocked a skill")
	}
}

func TestIndexBoundsLegacyMetadata(t *testing.T) {
	// Legacy user-edited skills do not necessarily enforce frontmatter limits.
	// Their metadata must not turn bounded excerpts into unbounded tool output.
	idx := New(skill.NewRegistry(
		skill.Skill{Name: strings.Repeat("n", maxNameBytes+1), Instructions: "oversizednameuniquemarker"},
		skill.Skill{Name: "normal", Description: strings.Repeat("x", maxDescriptionRunes) + " discardeddescriptionmarker", Instructions: "# " + strings.Repeat("權限", 2000)},
	))
	if !idx.truncated || len(idx.Categories()) != 1 {
		t.Fatal("metadata truncation must be bounded and disclosed")
	}
	for _, query := range []string{"oversizednameuniquemarker", "discardeddescriptionmarker"} {
		result, err := idx.Search(t.Context(), query, "", 1)
		if err != nil || len(result.Hits) != 0 {
			t.Fatal("discarded metadata leaked into the index", result, err)
		}
	}
	result, err := idx.Search(t.Context(), "權限", "", 1)
	if err != nil || len(result.Hits) != 1 || utf8.RuneCountInString(result.Hits[0].Heading) > 200 {
		t.Fatal("unbounded heading", result, err)
	}
}
