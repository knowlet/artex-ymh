package xaioauth

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
)

type oauthTransport struct {
	manager *Manager
	base    http.RoundTripper
}

// Transport resolves a current token for every inference request. It pins both
// the origin and allowed paths, including a second check on any redirected
// request. Configure the enclosing http.Client to reject redirects as well.
func (m *Manager) Transport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = m.client.Transport
	}
	return &oauthTransport{manager: m, base: base}
}

func validInferenceRequest(req *http.Request) bool {
	if req == nil || req.URL == nil {
		return false
	}
	u := req.URL
	if u.Scheme != "https" || u.Hostname() != "api.x.ai" || (u.Port() != "" && u.Port() != "443") || u.User != nil || u.Opaque != "" || u.Fragment != "" || u.RawPath != "" || u.RawQuery != "" {
		return false
	}
	return (u.Path == "/v1/responses" && req.Method == http.MethodPost) || (u.Path == "/v1/models" && req.Method == http.MethodGet)
}

func authenticatedRequest(req *http.Request, token string) *http.Request {
	copy := req.Clone(req.Context())
	copy.Header = req.Header.Clone()
	if copy.Header == nil {
		copy.Header = make(http.Header)
	}
	copy.Header.Set("Authorization", "Bearer "+token)
	copy.Host = ""
	return copy
}

func (t *oauthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !validInferenceRequest(req) {
		closeRequestBody(req)
		return nil, ErrUnsafeEndpoint
	}
	token, err := t.manager.Token(req.Context())
	if err != nil {
		closeRequestBody(req)
		return nil, err
	}
	resp, err := t.base.RoundTrip(authenticatedRequest(req, token))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return finishResponse(resp)
	}
	// Never replay a body that the caller cannot recreate. Streaming output has
	// not been delivered: this check happens at HTTP headers, before any read.
	if req.Body != nil && req.Body != http.NoBody && req.GetBody == nil {
		return sanitizeAuthResponse(resp), nil
	}
	closeResponse(resp)
	refreshed, err := t.manager.Refresh(req.Context(), token)
	if err != nil {
		return nil, err
	}
	retry := authenticatedRequest(req, refreshed)
	if req.GetBody != nil {
		retry.Body, err = req.GetBody()
		if err != nil {
			return nil, err
		}
	}
	resp, err = t.base.RoundTrip(retry)
	if err != nil {
		return nil, err
	}
	return finishResponse(resp)
}

func closeRequestBody(req *http.Request) {
	if req != nil && req.Body != nil {
		_ = req.Body.Close()
	}
}

func finishResponse(resp *http.Response) (*http.Response, error) {
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		closeResponse(resp)
		return nil, errors.New("xAI OAuth inference redirects are not allowed")
	}
	return sanitizeAuthResponse(resp), nil
}

func closeResponse(resp *http.Response) {
	if resp != nil && resp.Body != nil {
		// Do not drain an untrusted auth/redirect body: it may never finish.
		_ = resp.Body.Close()
	}
}

// Auth failures sometimes echo upstream details. Keep their status but only
// expose locally composed guidance; never forward token endpoint text or a
// response body that could contain a bearer token to logs/the model/UI.
func sanitizeAuthResponse(resp *http.Response) *http.Response {
	if resp == nil || (resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden) {
		return resp
	}
	message := ErrReauthRequired.Error()
	code := "xai_oauth_authentication_failed"
	if resp.StatusCode == http.StatusForbidden {
		message = ErrEntitlement.Error()
		code = "xai_oauth_entitlement_denied"
	}
	data, _ := json.Marshal(map[string]any{"error": map[string]string{"message": message, "type": "authentication_error", "code": code}})
	closeResponse(resp)
	copy := new(http.Response)
	*copy = *resp
	copy.Header = resp.Header.Clone()
	if copy.Header == nil {
		copy.Header = make(http.Header)
	}
	copy.Header.Set("Content-Type", "application/json")
	copy.Header.Set("Content-Length", strconv.Itoa(len(data)))
	copy.Header.Del("Content-Encoding")
	copy.Header.Del("WWW-Authenticate")
	copy.Body = io.NopCloser(strings.NewReader(string(data)))
	copy.ContentLength = int64(len(data))
	return copy
}
