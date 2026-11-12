package skillknowledge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/Autumn-27/norma/permission"
	"github.com/Autumn-27/norma/skill"
	actool "github.com/Autumn-27/norma/tool"
)

// Tools adapts AntiFox's knowledge-tool surface to ARTEX's existing per-agent
// skill visibility. Unlike AntiFox's knowledge service, this is offline lexical
// retrieval only: no global/task uploads, embeddings or network access.
func Tools(reg *skill.Registry) []actool.CoreTool {
	idx := New(reg)
	return []actool.CoreTool{
		readTool("search_knowledge", "檢索本次執行中目前代理可見技能的參考段落（離線關鍵字檢索，支援中文與英文）。結果不是目標證據；用 Skill 載入完整程序。檢索不會呼叫技能或解鎖 MCP。",
			map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{
				"query":    map[string]any{"type": "string", "maxLength": MaxQueryRunes, "description": "問題或主題，例如 SQL injection、權限驗證、證據報告"},
				"category": map[string]any{"type": "string", "description": "可選：list_knowledge_categories 回傳的完整技能名稱"},
				"top_k":    map[string]any{"type": "integer", "minimum": 0, "maximum": MaxLimit, "description": "回傳段落數，預設 5，上限 20"},
			}, "required": []string{"query"}},
			func(ctx context.Context, in json.RawMessage) (any, error) {
				var input struct {
					Query    string `json:"query"`
					Category string `json:"category"`
					TopK     int    `json:"top_k"`
				}
				if err := decode(in, &input); err != nil {
					return nil, err
				}
				return idx.Search(ctx, input.Query, input.Category, input.TopK)
			}),
		readTool("list_knowledge_categories", "列出本次執行中目前代理可檢索的技能名稱與簡述。僅包含已授予可見性的技能；不表示相依工具已安裝或可執行。",
			map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{}},
			func(ctx context.Context, in json.RawMessage) (any, error) {
				var input struct{}
				if err := decode(in, &input); err != nil {
					return nil, err
				}
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				return map[string]any{"categories": idx.Categories(), "scope": "visible skills in this run", "index_truncated": idx.truncated}, nil
			}),
	}
}

func decode(input json.RawMessage, out any) error {
	if len(input) > 8192 || !utf8.Valid(input) || len(bytes.TrimSpace(input)) == 0 || bytes.TrimSpace(input)[0] != '{' {
		return fmt.Errorf("input must be a bounded UTF-8 JSON object")
	}
	d := json.NewDecoder(bytes.NewReader(input))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("input must contain one JSON object")
	}
	return nil
}

func readTool(name, desc string, schema map[string]any, run func(context.Context, json.RawMessage) (any, error)) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: name, Description: desc, Schema: schema,
		ReadOnly:   func(json.RawMessage) bool { return true },
		Concurrent: func(json.RawMessage) bool { return true },
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			data, err := run(ctx, in)
			if err != nil {
				if ctx.Err() != nil {
					return actool.Result{}, ctx.Err()
				}
				return actool.Errorf(err.Error()), nil
			}
			b, err := json.Marshal(data)
			if err != nil {
				return actool.Result{}, err
			}
			return actool.Text(string(b)), nil
		},
	})
}
