package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

// decodeBoundedJSON reads the complete request before decoding it. In addition
// to limiting allocations, this rejects a second JSON value or an oversized
// whitespace/unknown-field suffix before callers perform any mutations.
func decodeBoundedJSON(w http.ResponseWriter, r *http.Request, value any, limit int64) bool {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	body, err := io.ReadAll(r.Body)
	if err == nil {
		err = json.Unmarshal(body, value)
	}
	if err == nil {
		return true
	}
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeErr(w, http.StatusRequestEntityTooLarge, "请求正文过大")
	} else {
		writeErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
	}
	return false
}
