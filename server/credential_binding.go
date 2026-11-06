package server

import (
	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/internal/endpoint"
)

// reuseLLMKey permits blank-key edits/tests only at the destination to which the
// stored secret belongs. An explicit replacement key authorizes a new endpoint.
func reuseLLMKey(dst *agent.Config, src agent.Config) error {
	if dst.APIKey != "" || src.APIKey == "" {
		return nil
	}
	a, err := endpoint.LLM(dst.Provider(), dst.BaseURL, dst.Proxy)
	if err != nil {
		return err
	}
	b, err := endpoint.LLM(src.Provider(), src.BaseURL, src.Proxy)
	if err != nil {
		return err
	}
	if a != b {
		return endpoint.ErrCredentialDestination
	}
	dst.APIKey = src.APIKey
	return nil
}

func resolveCredentialEndpoint(current, requested string, keepSecret bool) (string, error) {
	next, err := endpoint.URL(requested)
	if err != nil {
		return "", err
	}
	if keepSecret {
		stored, err := endpoint.URL(current)
		if err != nil || stored != next {
			return "", endpoint.ErrCredentialDestination
		}
	}
	return next, nil
}
