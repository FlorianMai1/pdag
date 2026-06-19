package audit

import (
	"encoding/json"
	"strconv"
	"strings"
)

// sanitizeBody prepares a request body for inclusion in an audit entry: it
// redacts the values of sensitive JSON fields (case-insensitive key match) and
// caps the result at maxBytes (0 = unlimited), truncating with a marker.
//
// A valid JSON body within the cap is embedded inline (as json.RawMessage);
// non-JSON or truncated content is embedded as a JSON string. Returns nil for
// an empty body.
func sanitizeBody(raw []byte, maxBytes int, redact map[string]bool) json.RawMessage {
	if len(raw) == 0 {
		return nil
	}

	out := raw
	valid := json.Valid(raw)
	if valid && len(redact) > 0 {
		var v any
		if err := json.Unmarshal(raw, &v); err == nil {
			if b, err := json.Marshal(redactValue(v, redact)); err == nil {
				out = b
			}
		}
	}

	if maxBytes > 0 && len(out) > maxBytes {
		// Truncated content is no longer valid JSON, so embed it as a string.
		return json.RawMessage(strconv.Quote(string(out[:maxBytes]) + "...(truncated)"))
	}
	if valid {
		return json.RawMessage(out)
	}
	return json.RawMessage(strconv.Quote(string(out)))
}

// redactValue walks a decoded JSON value and replaces the values of keys in the
// redact set (matched case-insensitively) with a redaction marker.
func redactValue(v any, redact map[string]bool) any {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if redact[strings.ToLower(k)] {
				t[k] = "[REDACTED]"
			} else {
				t[k] = redactValue(val, redact)
			}
		}
		return t
	case []any:
		for i, val := range t {
			t[i] = redactValue(val, redact)
		}
		return t
	default:
		return v
	}
}
