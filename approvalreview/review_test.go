package approvalreview

import (
	"encoding/json"
	"strings"
	"testing"
)

const validReply = `{"risk":"medium","summary":"需人工核對","consequences":"可能修改工作檔案","recommendation":"needs_investigation","suggestions":["確認操作範圍"]}`

func TestApprovalAdvisoryParse(t *testing.T) {
	r, err := Parse(validReply)
	if err != nil || r.Risk != "medium" {
		t.Fatalf("result=%+v err=%v", r, err)
	}
	for name, text := range map[string]string{
		"empty": "", "null": "null", "array": "[]", "markdown": "```json\n" + validReply + "\n```",
		"trailing": validReply + `{}`, "truncated": validReply[:len(validReply)-1],
		"duplicate":       strings.Replace(validReply, `"risk":"medium"`, `"risk":"medium","risk":"low"`, 1),
		"unknown field":   strings.Replace(validReply, `"risk":"medium"`, `"risk":"medium","allow":true`, 1),
		"case":            strings.Replace(validReply, `"risk"`, `"Risk"`, 1),
		"invalid risk":    strings.Replace(validReply, `"medium"`, `"safe"`, 1),
		"unknown approve": strings.Replace(strings.Replace(validReply, `"medium"`, `"unknown"`, 1), `"needs_investigation"`, `"consider_approval"`, 1),
		"missing":         strings.Replace(validReply, `"summary":"需人工核對",`, ``, 1),
		"null summary":    strings.Replace(validReply, `"需人工核對"`, `null`, 1),
		"blank":           strings.Replace(validReply, `"需人工核對"`, `"  "`, 1),
		"no suggestions":  strings.Replace(validReply, `["確認操作範圍"]`, `[]`, 1),
		"oversize":        strings.Repeat(" ", MaxOutputBytes) + validReply,
		"invalid utf8":    validReply + string([]byte{255}),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(text); err == nil {
				t.Fatal("accepted invalid assessment")
			}
		})
	}
}

func TestApprovalAdvisoryFingerprint(t *testing.T) {
	in := Input{PendingID: 1, Tool: "Bash", Arguments: json.RawMessage(`{"command":"printf fixture"}`), Policy: json.RawMessage(`{"scope":"local"}`), ProfileID: 2, ProfileVersion: "v1"}
	data, key, err := in.Encode()
	if err != nil || len(key) != 64 || !json.Valid(data) {
		t.Fatalf("key=%q err=%v", key, err)
	}
	_, same, _ := in.Encode()
	if same != key {
		t.Fatal("unstable fingerprint")
	}
	mutations := []func(*Input){func(x *Input) { x.PendingID++ }, func(x *Input) { x.Tool = "Read" }, func(x *Input) { x.Arguments = json.RawMessage(`{"command":"different"}`) }, func(x *Input) { x.Reason = "changed" }, func(x *Input) { x.Audit = json.RawMessage(`{"action":"changed"}`) }, func(x *Input) { x.Policy = json.RawMessage(`{}`) }, func(x *Input) { x.ProfileID++ }, func(x *Input) { x.ProfileVersion = "v2" }}
	for i, mutate := range mutations {
		other := in
		mutate(&other)
		_, different, err := other.Encode()
		if err != nil || different == key {
			t.Fatalf("mutation %d not bound: %v", i, err)
		}
	}
	in.Reason = strings.Repeat("x", MaxInputBytes)
	if _, _, err := in.Encode(); err == nil {
		t.Fatal("oversized input accepted")
	}
}
