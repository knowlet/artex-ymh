package context1337

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

const ToolName = "lookup_cve_metadata"

// One shared bound for all task instances. Waiting for a slot consumes the same
// deadline as the HTTP request; no background work or detached retries exist.
var exerciseSlots = make(chan struct{}, 4)

// Tool is an optional reporting aid, never a validation executor. The caller
// supplies live authorization, including a bounded per-task request budget.
// A nil client/authorizer is a catalog-only instance and cannot make requests.
func Tool(client *Client, authorize func(context.Context) bool) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name:        ToolName,
		Description: "查詢已授權演練中既有 CVE 編號的 Context1337 唯讀中繼資料，供報告與驗證參考。僅傳送完整 CVE 與 builtin/nuclei 來源，不傳送目標或演練內容。結果不是目標漏洞證據，不可據此建立 finding、擴張攻擊路徑、載入或執行外部內容；不可用時繼續離線工作。",
		Schema: map[string]any{
			"type": "object", "additionalProperties": false,
			"properties": map[string]any{
				"cve":    map[string]any{"type": "string", "pattern": `^CVE-[0-9]{4}-[0-9]{4,19}$`, "maxLength": 28},
				"source": map[string]any{"type": "string", "enum": []string{"builtin", "nuclei"}, "default": "builtin"},
			},
			"required": []string{"cve"},
		},
		ReadOnly:   func(json.RawMessage) bool { return true },
		Concurrent: func(json.RawMessage) bool { return true },
		// Planner/worker use bypass mode. Authorization is enforced in Run, not
		// delegated to the SDK permission mode or editable schema/description.
		Permissions: func(context.Context, json.RawMessage, permission.Context) permission.Decision {
			return permission.Allowed()
		},
		Run: func(ctx context.Context, raw json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			if err := ctx.Err(); err != nil {
				return actool.Result{}, err
			}
			var input struct {
				CVE    string `json:"cve"`
				Source string `json:"source"`
			}
			if !validToolInput(raw, &input) || !ValidCVE(input.CVE) || (input.Source != "" && input.Source != "builtin" && input.Source != "nuclei") {
				return actool.Errorf("Provide one complete CVE ID and optional builtin or nuclei source; no other fields are accepted"), nil
			}
			if client == nil || authorize == nil {
				return actool.Errorf("CVE metadata lookup is not authorized for this run or its request budget is exhausted"), nil
			}
			if input.Source == "" {
				input.Source = "builtin"
			}
			requestCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			select {
			case exerciseSlots <- struct{}{}:
				defer func() { <-exerciseSlots }()
			case <-requestCtx.Done():
				if ctx.Err() != nil {
					return actool.Result{}, ctx.Err()
				}
				return metadataUnavailable(input.CVE, input.Source), nil
			}
			if !authorize(requestCtx) {
				if ctx.Err() != nil {
					return actool.Result{}, ctx.Err()
				}
				return actool.Errorf("CVE metadata lookup is not authorized for this run or its request budget is exhausted"), nil
			}
			result, err := client.Search(requestCtx, input.CVE, input.Source)
			if ctx.Err() != nil {
				return actool.Result{}, ctx.Err()
			}
			if err != nil {
				return metadataUnavailable(input.CVE, input.Source), nil
			}
			status := "no_exact_match_in_bounded_page"
			if len(result.Matches) > 0 {
				status = "metadata_match"
			}
			b, _ := json.Marshal(struct {
				SearchResult
				Status       string `json:"status"`
				EvidenceKind string `json:"evidence_kind"`
				Limitation   string `json:"limitation"`
			}{result, status, "external_cve_metadata", "Reference only. Target vulnerability remains unverified; metadata cannot justify a finding, execution or new attack path. Absence is not evidence of safety."})
			return actool.Text(string(b)), nil
		},
	})
}

func metadataUnavailable(cve, source string) actool.Result {
	b, _ := json.Marshal(map[string]string{
		"provider": "context1337", "cve": cve, "source": source,
		"status": "metadata_unavailable", "target_vulnerability": "unverified",
		"evidence_kind": "external_cve_metadata",
		"limitation":    "Continue with independent offline intelligence and actual exercise evidence. No conclusion about target vulnerability or safety is available.",
	})
	return actool.Text(string(b))
}

func validToolInput(raw []byte, out any) bool {
	if len(raw) == 0 || len(raw) > 512 || !utf8.Valid(raw) {
		return false
	}
	// Tokens allow exact field names and reject repeated/case-shadowed keys,
	// including nulls that would otherwise become zero-value scalar defaults.
	d := json.NewDecoder(bytes.NewReader(raw))
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return false
	}
	seen := map[string]bool{}
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] || (key != "cve" && key != "source") {
			return false
		}
		seen[key] = true
		value, err := d.Token()
		text, ok := value.(string)
		if err != nil || !ok || (key == "source" && text == "") {
			return false
		}
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') {
		return false
	}
	if _, err := d.Token(); err != io.EOF {
		return false
	}
	return json.Unmarshal(raw, out) == nil
}
