package agent

import (
	"strings"
	"testing"
)

func TestOpenAIWireTransientFailuresPreserveClassification(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		transient bool
	}{
		{"overload", `data: {"error":{"type":"overloaded_error","message":"fixture-private"}}` + "\n\n", true},
		{"rate", `data: {"error":{"type":"rate_limit_error","message":"fixture-private"}}` + "\n\n", true},
		{"eof", `data: {"choices":[{"index":0,"delta":{"content":"fixture text"}}]}` + "\n\n", true},
		{"dsml", `data: {"choices":[{"index":0,"delta":{"content":"<｜DSML｜tool_calls <｜DSML｜invoke"}}]}` + "\n\n", false},
		{"quota", `data: {"error":{"type":"insufficient_quota","message":"fixture-private"}}` + "\n\n", false},
		{"auth", `data: {"error":{"type":"authentication_error","message":"fixture-private"}}` + "\n\n", false},
		{"unknown", `data: {"error":{"message":"fixture-private"}}` + "\n\n", false},
		{"malformed", `data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"a","type":"function","function":{"name":"get_worker_trace","arguments":"{"}}]}}]}` + "\n\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _, ctx := toolWireFixture(t, tc.raw, true)
			var got error
			for _, err := range p.Stream(ctx, toolWireRequest()) {
				if err != nil {
					got = err
				}
			}
			if got == nil || IsTransientModelError(got) != tc.transient {
				t.Fatalf("error=%v retryable=%v want=%v", got, IsTransientModelError(got), tc.transient)
			}
			if strings.Contains(got.Error(), "fixture-private") {
				t.Fatal("upstream payload leaked")
			}
		})
	}
}
