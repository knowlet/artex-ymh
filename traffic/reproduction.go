// SPDX-License-Identifier: AGPL-3.0-or-later
// Reproduction-step ↔ traffic exchange linkage (logic adapted from AntiFox-AI/antifox, AGPL-3.0).

package traffic

import (
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// ResolveStepExchange maps a reproduction step back to the real recorded exchange it
// cites. A confirmed vuln step corresponds to a real request the agent sent (through
// the MITM proxy) that got a real response — so a matching exchange should exist. The
// step's "request" may be a verbatim HTTP packet OR the command the agent ran (curl /
// shell); parseStepRequest handles both. Strategy: start from a broad method+host+path
// pool, then PROGRESSIVELY narrow by each available discriminator (request body/query,
// then distinctive tokens from the response) — applying a narrowing ONLY while it
// keeps ≥1 candidate, so an over-specific or paraphrased field never drops the match
// to zero. Finally prefer the SUCCESSFUL exchange (the step's stated status, else a
// 2xx — vuln steps usually return 200), newest. Abstains only when nothing but the
// bare endpoint matched (still genuinely ambiguous) or the endpoint isn't recorded.
func (t *Traffic) ResolveStepExchange(reqText, respText string) (string, bool) {
	method, host, path, query, bodyToken := parseStepRequest(reqText)
	if method == "" || path == "" {
		return "", false
	}
	where, args := reproBaseWhere(method, host, path)
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

type reproCand struct {
	id     string
	ts     int64
	status int
}

// pickBest resolves the final candidate set CONFIDENTLY: a single candidate, or —
// when content discriminators narrowed to several that differ only by outcome (e.g.
// a 200 exec and a later 404 of the same request) — the one with a UNIQUE matching
// status (the step's stated status, else the sole 2xx). It abstains when nothing but
// the bare endpoint matched, or the status doesn't single one out — never guessing
// among equals (a wrong evidence link is worse than none).
func (t *Traffic) pickBest(where string, args []any, wantStatus int, narrowed bool) (string, bool) {
	cands := t.queryCandidates(where, args, 50, "DESC")
	cands = filterByExpectedStatus(cands, wantStatus)
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

// pickEarliestDisambiguated is like pickBest but chooses the chronologically earliest
// match (multi-step ordered resolution) and requires content narrowing before
// committing when multiple rows remain.
func (t *Traffic) pickEarliestDisambiguated(where string, args []any, wantStatus int, narrowed bool) (string, int64, bool) {
	cands := t.queryCandidates(where, args, 50, "ASC")
	cands = filterByExpectedStatus(cands, wantStatus)
	switch {
	case len(cands) == 0:
		return "", 0, false
	case len(cands) == 1:
		return cands[0].id, cands[0].ts, true
	case !narrowed:
		return "", 0, false
	}
	uniq := func(pred func(int) bool) (reproCand, bool) {
		var hit reproCand
		n := 0
		for _, c := range cands {
			if pred(c.status) {
				hit, n = c, n+1
			}
		}
		return hit, n == 1
	}
	if wantStatus > 0 {
		if c, ok := uniq(func(s int) bool { return s == wantStatus }); ok {
			return c.id, c.ts, true
		}
	}
	if c, ok := uniq(func(s int) bool { return s >= 200 && s < 300 }); ok {
		return c.id, c.ts, true
	}
	return "", 0, false
}

// filterByExpectedStatus drops exchanges whose status contradicts an explicit step
// expectation (e.g. don't link a 404 probe when the step documents HTTP 200).
func filterByExpectedStatus(cands []reproCand, wantStatus int) []reproCand {
	if wantStatus <= 0 {
		return cands
	}
	out := cands[:0]
	for _, c := range cands {
		if c.status == wantStatus {
			out = append(out, c)
		}
	}
	return out
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

func (t *Traffic) queryCandidates(where string, args []any, limit int, tsOrder string) []reproCand {
	if tsOrder != "ASC" && tsOrder != "DESC" {
		tsOrder = "DESC"
	}
	rows, err := t.db.Query(`SELECT id, ts, status FROM exchanges WHERE `+where+
		` ORDER BY ts `+tsOrder+`, id `+tsOrder+` LIMIT ?`, append(append([]any{}, args...), limit)...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var cands []reproCand
	for rows.Next() {
		var c reproCand
		if rows.Scan(&c.id, &c.ts, &c.status) == nil {
			cands = append(cands, c)
		}
	}
	return cands
}

// ExchangeTS returns the indexed capture timestamp for an exchange id.
func (t *Traffic) ExchangeTS(id string) (int64, bool) {
	var ts int64
	if err := t.db.QueryRow(`SELECT ts FROM exchanges WHERE id=?`, id).Scan(&ts); err != nil {
		return 0, false
	}
	return ts, true
}

// StepRef is one reproduction step's verbatim request/response text, to be resolved
// to the real recorded exchange that cites it.
type StepRef struct {
	Request    string
	Response   string
	ExchangeID string // already linked — advances cursor, never reused for another step
}

// ResolveSteps maps an ORDERED list of reproduction steps to real recorded exchanges,
// constrained to the task's traffic time window [sinceUnix, untilUnix] (Unix seconds).
// Steps resolve in order — each step's exchange must come at-or-after the previous
// step's (agents list steps chronologically), which disambiguates repeated identical
// requests: of many identical requests to one endpoint, step 1 is the earliest, step 2 the
// next after it, and so on. Per step: narrow method+host+exact path to the window, then
// refine by body/query/response discriminators (each applied only while ≥1 candidate
// remains), exclude previously linked exchange ids, then pick the EARLIEST disambiguated
// match. Returns one exchange id per step ("" when unresolved).
func (t *Traffic) ResolveSteps(sinceUnix, untilUnix int64, steps []StepRef) []string {
	out := make([]string, len(steps))
	cursor := int64(0)
	used := map[string]bool{}
	for i, st := range steps {
		if st.ExchangeID != "" {
			out[i] = st.ExchangeID
			used[st.ExchangeID] = true
			if ts, ok := t.ExchangeTS(st.ExchangeID); ok {
				cursor = ts
			}
			continue
		}
		method, host, path, query, bodyToken := parseStepRequest(st.Request)
		if method == "" || path == "" {
			continue
		}
		if id, ts, ok := t.resolveStepInWindow(sinceUnix, untilUnix, cursor, used, method, host, path, query, bodyToken, st.Response); ok {
			out[i] = id
			used[id] = true
			cursor = ts
		}
	}
	return out
}

// resolveStepInWindow finds the earliest exchange matching one step, at-or-after
// cursor, inside the task's time window. Returns (id, ts, ok).
func (t *Traffic) resolveStepInWindow(sinceUnix, untilUnix, cursor int64, used map[string]bool, method, host, path, query, bodyToken, respText string) (string, int64, bool) {
	where, args := reproBaseWhere(method, host, path)
	where += ` AND ts BETWEEN ? AND ? AND ts >= ?`
	args = append(args, sinceUnix, untilUnix, cursor)
	if cond, cargs := sqlNotInIDs(used); cond != "" {
		where += cond
		args = append(args, cargs...)
	}
	narrowed := false
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
	return t.pickEarliestDisambiguated(where, args, expectedStatus(respText), narrowed)
}

func reproBaseWhere(method, host, path string) (string, []any) {
	path = templatePathForMatch(path)
	where := `method=? AND url_template=?`
	args := []any{strings.ToUpper(method), path}
	if h := strings.TrimSpace(host); h != "" {
		where += ` AND LOWER(host)=LOWER(?)`
		args = append(args, h)
	}
	return where, args
}

func sqlNotInIDs(used map[string]bool) (string, []any) {
	if len(used) == 0 {
		return "", nil
	}
	ids := make([]string, 0, len(used))
	for id := range used {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	place := strings.Repeat("?,", len(ids))
	place = place[:len(place)-1]
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	return ` AND id NOT IN (` + place + `)`, args
}

func normalizeReqPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	return p
}

// templatePathForMatch canonicalizes a step path the same way record() templates
// url_template so /users/123 matches the indexed /users/{id}.
func templatePathForMatch(p string) string {
	p = normalizeReqPath(p)
	if p == "" {
		p = "/"
	}
	return db.TemplatePath(p)
}

// Reproduction-step request parsing: a step's "request" is either a verbatim HTTP
// packet or the command the agent ran (curl/shell). Both forms are resolved to the
// real recorded exchange via these patterns.
var (
	reHTTPReqLine = regexp.MustCompile(`^([A-Z]+)\s+(\S+)\s+HTTP/\S+\s*$`)
	reURLInText   = regexp.MustCompile("https?://[^\\s\"'`;)<>]+")
	reCurlMethod  = regexp.MustCompile(`(?:^|\s)-X\s*=?([A-Za-z]+)|(?:^|\s)--request(?:=|\s+)([A-Za-z]+)`)
	reHostHeader  = regexp.MustCompile(`(?i)^Host:\s*(\S+)`)
	reBodyFlag    = regexp.MustCompile(`(?:^|\s)(?:-F|--form|-d|--data|--data-raw|--data-binary)(?:\s|=)`)
	reUploadName  = regexp.MustCompile(`filename=["']?([^"'\s;,]+)`)
	reCurlData    = regexp.MustCompile(`(?:-d|--data(?:-raw|-binary)?)[ =]\s*["']?([^"'\n]+)`)
)

// parseStepRequest extracts method, host, url PATH (query stripped), the url QUERY, and a
// body discriminator token from a step's request text — whether it's a raw HTTP
// request packet ("METHOD /path?q PROTO\n…\n\n<body>") or a curl/shell command the
// agent executed. query (for GET-style requests) and the body token (upload filename
// / POST data / leading body slice) disambiguate same-endpoint requests; both may be
// empty when nothing distinctive is present.
func parseStepRequest(text string) (method, host, path, query, bodyToken string) {
	// 1) Raw HTTP request packet.
	if m := reHTTPReqLine.FindStringSubmatch(firstNonEmptyLine(text)); m != nil {
		method = strings.ToUpper(m[1])
		path, query = splitQuery(m[2])
		host = parseHostHeader(text)
		_, body := splitHTTPBody(text)
		if body != "" {
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
		return "", "", "", "", ""
	}
	if parsed, err := url.Parse(u); err == nil && parsed.Host != "" {
		host = parsed.Hostname()
		path, query = parsed.Path, parsed.RawQuery
		if path == "" {
			path = "/"
		}
	} else {
		path, query = splitQuery(u)
	}
	if method = parseCurlMethod(text); method == "" {
		if reBodyFlag.MatchString(text) {
			method = "POST"
		} else {
			method = "GET"
		}
	}
	if method != "GET" && method != "HEAD" {
		if m := reUploadName.FindStringSubmatch(text); m != nil {
			bodyToken = m[1]
		} else if m := reCurlData.FindStringSubmatch(text); m != nil {
			bodyToken = bodyPhrase(m[1])
		}
	}
	return
}

func parseCurlMethod(text string) string {
	if m := reCurlMethod.FindStringSubmatch(text); len(m) >= 1 {
		for _, g := range m[1:] {
			if g != "" {
				return strings.ToUpper(g)
			}
		}
	}
	return ""
}

func parseHostHeader(text string) string {
	for _, ln := range strings.Split(text, "\n") {
		ln = strings.TrimSpace(strings.TrimSuffix(ln, "\r"))
		if m := reHostHeader.FindStringSubmatch(ln); m != nil {
			h := m[1]
			if i := strings.IndexByte(h, ':'); i >= 0 {
				h = h[:i]
			}
			return strings.ToLower(h)
		}
	}
	return ""
}

func splitHTTPBody(text string) (headers, body string) {
	if i := strings.Index(text, "\r\n\r\n"); i >= 0 {
		return text[:i], text[i+4:]
	}
	if i := strings.Index(text, "\n\n"); i >= 0 {
		return text[:i], text[i+2:]
	}
	return text, ""
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
