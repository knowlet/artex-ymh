package agent

import "testing"

func TestSecurityAssetInputLabelMasksURLCredentials(t *testing.T) {
	input := assetInputItem{Type: "endpoint", URL: "https://fixture-user:fixture-secret@example.test/path"}
	if got := assetInputLabel(input); got != "[endpoint] https://REDACTED@example.test/path" {
		t.Fatalf("asset rejection label = %q", got)
	}
}
