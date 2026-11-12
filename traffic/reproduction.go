// SPDX-License-Identifier: AGPL-3.0-or-later
// Reproduction-step ↔ traffic exchange linkage (logic adapted from AntiFox-AI/antifox, AGPL-3.0).

package traffic

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// ResolveStepExchange maps a reproduction step back to the real recorded exchange it
// cites. A confirmed vuln step corresponds to a real request the agent sent (through
// the MITM proxy) that got a real response — so a matching exchange should exist. The
// step's "request" may be a verbatim HTTP packet OR the command the agent ran (curl /
// shell); parseStepRequest handles both. Strategy: start from a broad method+path
// pool, then PROGRESSIVELY narrow by each available discriminator (request body/query,
// then distinctive tokens from the response) — applying a narrowing ONLY while it
// keeps ≥1 candidate, so an over-specific or paraphrased field never drops the match
// to zero. Finally prefer the SUCCESSFUL exchange (the step's stated status, else a
// 2xx — vuln steps usually return 200), newest. Abstains only when nothing but the
// bare endpoint matched (still genuinely ambiguous) or the endpoint isn't recorded.
func (t *Traffic) ResolveStepExchange(reqText, respText string) (string, bool) {
	method, path, query, bodyToken := parseStepRequest(reqText)
	if method == "" || path == "" {
		return "", false
	}
	where := `method=? AND url LIKE ? ESCAPE '\'`
	args := []any{strings.ToUpper(method), likeContains(path)}
	narrowed := false
	// tryNarrow appends a condition only if it still leaves at least one candidate.
	tryNarrow := func(cond string, arg any) {
		w, a := where+" AND "+cond, append(append([]any{}, args...), arg)
		if len(t.queryIDs(w, a)) >= 1 {
			where, args, narrowed = w, a, true
		}
	}
	if t.fts && bodyToken != "" {
		tryNarrow("rowid IN (SELECT rowid FROM ex_fts WHERE ex_fts MATCH ?)", ftsQuote(bodyToken))
	}
	if query != "" {
		// Escape LIKE metacharacters — URL-encoded payloads are full of % (%27,%20…).
		tryNarrow(`url LIKE ? ESCAPE '\'`, likeContains(query))
	}
	if t.fts {
		for _, disc := range respDiscriminators(respText) {
			if len(t.queryIDs(where, args)) <= 1 {
				break
			}
			tryNarrow("rowid IN (SELECT rowid FROM ex_fts WHERE ex_fts MATCH ?)", ftsQuote(disc))
		}
	}
	return t.pickBest(where, args, expectedStatus(respText), narrowed)
}

// pickBest resolves the final candidate set CONFIDENTLY: a single candidate, or —
// when content discriminators narrowed to several that differ only by outcome (e.g.
// a 200 exec and a later 404 of the same request) — the one with a UNIQUE matching
// status (the step's stated status, else the sole 2xx). It abstains when nothing but
// the bare endpoint matched, or the status doesn't single one out — never guessing
// among equals (a wrong evidence link is worse than none).
func (t *Traffic) pickBest(where string, args []any, wantStatus int, narrowed bool) (string, bool) {
	rows, err := t.db.Query(`SELECT id, status FROM exchanges WHERE `+where+` ORDER BY ts DESC LIMIT 50`, args...)
	if err != nil {
		return "", false
	}
	defer rows.Close()
	type cand struct {
		id     string
		status int
	}
	var cands []cand
	for rows.Next() {
		var c cand
		if rows.Scan(&c.id, &c.status) == nil {
			cands = append(cands, c)
		}
	}
	switch {
	case len(cands) == 0:
		return "", false
	case len(cands) == 1:
		return cands[0].id, true
	case !narrowed:
		return "", false // only the endpoint matched, still many → too ambiguous
	}
	// ≥2 content-matched candidates: resolve only on a UNIQUE status match.
	uniq := func(pred func(int) bool) (string, bool) {
		var hit string
		n := 0
		for _, c := range cands {
			if pred(c.status) {
				hit, n = c.id, n+1
			}
		}
		return hit, n == 1
	}
	if wantStatus > 0 {
		if id, ok := uniq(func(s int) bool { return s == wantStatus }); ok {
			return id, true
		}
	}
	if id, ok := uniq(func(s int) bool { return s >= 200 && s < 300 }); ok {
		return id, true
	}
	return "", false // still ambiguous → abstain
}

// expectedStatus extracts the HTTP status a step's response states (e.g. "HTTP/1.1
// 200 OK" / "HTTP 200"), or 0 when none is given.
func expectedStatus(respText string) int {
	if m := reStatusLine.FindStringSubmatch(respText); m != nil {
		n, _ := strconv.Atoi(m[1])
		return n
	}
	return 0
}

var reStatusLine = regexp.MustCompile(`(?i)HTTP[/0-9.]*\s+([1-5]\d\d)\b`)

// likeContains builds a `%…%` LIKE pattern with the inner value's LIKE metacharacters
// (\ % _) escaped — use with `ESCAPE '\'` so URL-encoded payloads match literally.
func likeContains(s string) string {
	return "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s) + "%"
}

// respDiscriminators returns candidate strings from a step's response, in priority
// order, to disambiguate same-request exchanges: distinctive long tokens first (they
// survive "…" paraphrasing), then the verbatim leading slice.
func respDiscriminators(resp string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range reLongToken.FindAllString(resp, -1) {
		if len(out) >= 5 {
			break
		}
		if !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	if p := bodyPhrase(resp); p != "" {
		out = append(out, p)
	}
	return out
}

var reLongToken = regexp.MustCompile(`[A-Za-z0-9]{8,}`)

// queryIDs returns up to 10 exchange ids matching where (newest first).
func (t *Traffic) queryIDs(where string, args []any) []string {
	rows, err := t.db.Query(`SELECT id FROM exchanges WHERE `+where+` ORDER BY ts DESC LIMIT 10`, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	return ids
}

// StepRef is one reproduction step's verbatim request/response text, to be resolved
// to the real recorded exchange that cites it.
type StepRef struct {
	Request  string
	Response string
}

// ResolveSteps maps an ORDERED list of reproduction steps to real recorded exchanges,
// constrained to the task's traffic time window [sinceUnix, untilUnix] (Unix seconds).
// Steps resolve in order — each step's exchange must come at-or-after the previous
// step's (agents list steps chronologically), which disambiguates repeated identical
// requests: of many identical requests to one endpoint, step 1 is the earliest, step 2 the
// next after it, and so on. Per step: narrow method+path to the window, then refine by
// body/query/response discriminators (each applied only while ≥1 candidate remains —
// an over-specific or paraphrased field never drops the match to zero), then pick the
// EARLIEST candidate at-or-after the previous step's timestamp. Returns one exchange
// id per step ("" when unresolved).
func (t *Traffic) ResolveSteps(sinceUnix, untilUnix int64, steps []StepRef) []string {
	out := make([]string, len(steps))
	cursor := int64(0) // previous step's exchange ts (chronological lower bound)
	for i, st := range steps {
		method, path, query, bodyToken := parseStepRequest(st.Request)
		if method == "" || path == "" {
			continue
		}
		if id, ts, ok := t.resolveStepInWindow(sinceUnix, untilUnix, cursor, method, path, query, bodyToken, st.Response); ok {
			out[i] = id
			cursor = ts
		}
	}
	return out
}

// resolveStepInWindow finds the earliest exchange matching one step, at-or-after
// cursor, inside the task's time window. Returns (id, ts, ok).
func (t *Traffic) resolveStepInWindow(sinceUnix, untilUnix, cursor int64, method, path, query, bodyToken, respText string) (string, int64, bool) {
	where := `method=? AND url LIKE ? ESCAPE '\' AND ts BETWEEN ? AND ? AND ts >= ?`
	args := []any{strings.ToUpper(method), likeContains(path), sinceUnix, untilUnix, cursor}
	// tryNarrow applies a discriminator only if it still leaves ≥1 candidate, so a
	// paraphrased/over-specific field can't zero out a match that should succeed.
	tryNarrow := func(cond string, arg any) {
		w, a := where+" AND "+cond, append(append([]any{}, args...), arg)
		if len(t.queryIDs(w, a)) >= 1 {
			where, args = w, a
		}
	}
	if t.fts && bodyToken != "" {
		tryNarrow("rowid IN (SELECT rowid FROM ex_fts WHERE ex_fts MATCH ?)", ftsQuote(bodyToken))
	}
	if query != "" {
		tryNarrow(`url LIKE ? ESCAPE '\'`, likeContains(query))
	}
	if t.fts {
		for _, disc := range respDiscriminators(respText) {
			if len(t.queryIDs(where, args)) <= 1 {
				break
			}
			tryNarrow("rowid IN (SELECT rowid FROM ex_fts WHERE ex_fts MATCH ?)", ftsQuote(disc))
		}
	}
	var id string
	var ts int64
	if err := t.db.QueryRow(`SELECT id, ts FROM exchanges WHERE `+where+` ORDER BY ts ASC LIMIT 1`, args...).Scan(&id, &ts); err != nil {
		return "", 0, false
	}
	return id, ts, true
}

// Reproduction-step request parsing: a step's "request" is either a verbatim HTTP
// packet or the command the agent ran (curl/shell). Both forms are resolved to the
// real recorded exchange via these patterns.
var (
	reHTTPReqLine = regexp.MustCompile(`^([A-Z]+)\s+(\S+)\s+HTTP/\S+\s*$`)
	reURLInText   = regexp.MustCompile("https?://[^\\s\"'`;)<>]+")
	reCurlMethod  = regexp.MustCompile(`(?:-X|--request)\s+([A-Za-z]+)`)
	reBodyFlag    = regexp.MustCompile(`(?:^|\s)(?:-F|--form|-d|--data|--data-raw|--data-binary)(?:\s|=)`)
	reUploadName  = regexp.MustCompile(`filename=["']?([^"'\s;,]+)`)
	reCurlData    = regexp.MustCompile(`(?:-d|--data(?:-raw|-binary)?)[ =]\s*["']?([^"'\n]+)`)
)

// parseStepRequest extracts method, url PATH (query stripped), the url QUERY, and a
// body discriminator token from a step's request text — whether it's a raw HTTP
// request packet ("METHOD /path?q PROTO\n…\n\n<body>") or a curl/shell command the
// agent executed. query (for GET-style requests) and the body token (upload filename
// / POST data / leading body slice) disambiguate same-endpoint requests; both may be
// empty when nothing distinctive is present.
func parseStepRequest(text string) (method, path, query, bodyToken string) {
	// 1) Raw HTTP request packet.
	if m := reHTTPReqLine.FindStringSubmatch(firstNonEmptyLine(text)); m != nil {
		method = strings.ToUpper(m[1])
		path, query = splitQuery(m[2])
		if i := strings.Index(text, "\n\n"); i >= 0 {
			body := text[i+2:]
			// Prefer the upload filename (strongest discriminator, and avoids a whole-body
			// FTS miss when the agent paraphrased the multipart boundary as a placeholder).
			if m := reUploadName.FindStringSubmatch(body); m != nil {
				bodyToken = m[1]
			} else {
				bodyToken = bodyPhrase(body)
			}
		}
		return
	}
	// 2) curl / shell command citing a target URL.
	u := reURLInText.FindString(text)
	if u == "" {
		return "", "", "", ""
	}
	if parsed, err := url.Parse(u); err == nil && parsed.Path != "" {
		path, query = parsed.Path, parsed.RawQuery
	} else {
		path, query = splitQuery(u)
	}
	if m := reCurlMethod.FindStringSubmatch(text); m != nil {
		method = strings.ToUpper(m[1])
	} else if reBodyFlag.MatchString(text) {
		method = "POST"
	} else {
		method = "GET"
	}
	// Body discriminator only for body-bearing methods (GET/HEAD have none indexed).
	if method != "GET" && method != "HEAD" {
		if m := reUploadName.FindStringSubmatch(text); m != nil {
			bodyToken = m[1]
		} else if m := reCurlData.FindStringSubmatch(text); m != nil {
			bodyToken = bodyPhrase(m[1])
		}
	}
	return
}

func firstNonEmptyLine(s string) string {
	for _, ln := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(ln); t != "" {
			return t
		}
	}
	return ""
}

func splitQuery(target string) (path, query string) {
	if i := strings.IndexByte(target, '?'); i >= 0 {
		return target[:i], target[i+1:]
	}
	return target, ""
}

// bodyPhrase returns a verbatim leading slice of the body to use as the trigram
// disambiguator (empty when too short for trigram). Capped so the FTS phrase stays
// cheap while still covering the discriminating value (usually early in the body).
func bodyPhrase(body string) string {
	b := strings.TrimSpace(body)
	r := []rune(b)
	if len(r) < 3 {
		return ""
	}
	if len(r) > 400 {
		r = r[:400]
	}
	return string(r)
}
