package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/internal/llmwire"
	"github.com/Autumn-27/norma/llm"
)

var modelHTTPStatus = regexp.MustCompile(`(?i)(?:status(?:\s+code)?|http(?:\s+status)?)\s*[=:]?\s*(\d{3})\b`)

// IsTransientModelError recognizes failures which can recover without changing
// the request, credentials or model configuration. Callers must also check their
// own context before retrying: a per-call timeout is retryable, a task deadline
// or user cancellation is not. Unknown errors fail closed.
func IsTransientModelError(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) {
		return false
	}
	s := strings.ToLower(err.Error())
	// Gateways use several names for the same context overflow. Replaying an
	// unchanged request cannot repair it, even when an outer gateway emits 5xx.
	for _, marker := range []string{"contextwindowexceeded", "context_window_exceeded", "context length", "context_length", "maximum context", "too long", "unparsed_dsml", "invalid_tool_call", "invalid tool call", "malformed tool"} {
		if strings.Contains(s, marker) {
			return false
		}
	}
	if IsQuotaExhaustedMessage(s) {
		return false
	}
	var wireErr *llmwire.ProtocolError
	if errors.As(err, &wireErr) {
		return wireErr.Transient()
	}
	if match := modelHTTPStatus.FindStringSubmatch(s); len(match) == 2 {
		code, _ := strconv.Atoi(match[1])
		return code == 408 || code == 429 || code >= 500 && code <= 599
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && (netErr.Timeout() || netErr.Temporary()) {
		return true
	}
	for _, marker := range []string{
		"unexpected eof", "connection reset", "connection refused", "connection closed",
		"broken pipe", "network is unreachable", "no route to host", "temporary network error",
		"i/o timeout", "tls handshake timeout", "timeout awaiting response headers",
		"overloaded_error", "server overloaded", "rate_limit_error", "rate limit exceeded", "too many requests",
	} {
		if strings.Contains(s, marker) {
			return true
		}
	}
	return s == "eof"
}

// Norma's reactive compactor recognizes "context length", but several
// LiteLLM/vLLM responses expose only the exception class. Preserve the original
// error and add the narrowly recognized equivalent for that existing recovery.
func normalizeContextOverflow(err error) error {
	if err == nil {
		return nil
	}
	s := strings.ToLower(err.Error())
	if strings.Contains(s, "contextwindowexceeded") || strings.Contains(s, "context_window_exceeded") {
		return fmt.Errorf("llm context length exceeded: %w", err)
	}
	return err
}

type modelErrorProvider struct{ inner llm.Provider }

func (p modelErrorProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	return func(yield func(llm.StreamEvent, error) bool) {
		for event, err := range p.inner.Stream(ctx, req) {
			if !yield(event, normalizeContextOverflow(err)) || err != nil {
				return
			}
		}
	}
}

func (p modelErrorProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	msg, stop, usage, err := p.inner.Complete(ctx, req)
	return msg, stop, usage, normalizeContextOverflow(err)
}
