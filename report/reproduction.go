package report

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Reproduction is the structured 复现过程 captured in-situ at report_finding
// (entry_point / prerequisites / ordered steps / provenance).
type Reproduction struct {
	EntryPoint    string      `json:"entry_point"`
	Prerequisites []string    `json:"prerequisites"`
	Steps         []ReproStep `json:"steps"`
	Provenance    string      `json:"provenance"`
}

// ReproStep is one ordered reproduction step. ExchangeID links to a recorded MITM
// exchange when resolved (for UI jump-to-traffic).
type ReproStep struct {
	Request    string `json:"request"`
	Response   string `json:"response"`
	Expected   string `json:"expected"`
	Proves     string `json:"proves"`
	ExchangeID string `json:"exchange_id,omitempty"`
}

// ReproductionMarkdown renders structured reproduction for export / reports.
// Returns "" when absent or unparseable.
func ReproductionMarkdown(raw json.RawMessage) string {
	if len(raw) < 3 {
		return ""
	}
	var r Reproduction
	if json.Unmarshal(raw, &r) != nil {
		return ""
	}
	var b strings.Builder
	if s := strings.TrimSpace(r.EntryPoint); s != "" {
		fmt.Fprintf(&b, "**入口点：** `%s`\n\n", s)
	}
	if pre := nonEmptyStrings(r.Prerequisites); len(pre) > 0 {
		b.WriteString("**前置条件：**\n\n")
		for _, p := range pre {
			fmt.Fprintf(&b, "- %s\n", p)
		}
		b.WriteString("\n")
	}
	if len(r.Steps) > 0 {
		b.WriteString("**复现步骤：**\n\n")
		for i, st := range r.Steps {
			fmt.Fprintf(&b, "#### 步骤 %d\n\n", i+1)
			if e := strings.TrimSpace(st.Expected); e != "" {
				fmt.Fprintf(&b, "- **预期：** %s\n", e)
			}
			if p := strings.TrimSpace(st.Proves); p != "" {
				fmt.Fprintf(&b, "- **证明：** %s\n", p)
			}
			if st.ExchangeID != "" {
				fmt.Fprintf(&b, "- **关联流量：** `%s`\n", st.ExchangeID)
			}
			b.WriteString("\n")
			if req := strings.TrimSpace(st.Request); req != "" {
				b.WriteString("**请求：**\n\n```http\n")
				b.WriteString(req)
				b.WriteString("\n```\n\n")
			}
			if resp := strings.TrimSpace(st.Response); resp != "" {
				b.WriteString("**响应：**\n\n```http\n")
				b.WriteString(resp)
				b.WriteString("\n```\n\n")
			}
		}
	}
	if s := strings.TrimSpace(r.Provenance); s != "" {
		fmt.Fprintf(&b, "**来源：** %s\n\n", s)
	}
	return strings.TrimSpace(b.String())
}

func nonEmptyStrings(in []string) []string {
	var out []string
	for _, s := range in {
		if t := strings.TrimSpace(s); t != "" {
			out = append(out, t)
		}
	}
	return out
}
