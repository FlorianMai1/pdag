package audit

import (
	"encoding/json"
	"strings"
	"testing"
)

func redactSet(fields ...string) map[string]bool {
	m := make(map[string]bool, len(fields))
	for _, f := range fields {
		m[f] = true
	}
	return m
}

func TestSanitizeBodyRedactsNestedFields(t *testing.T) {
	raw := []byte(`{"name":"k","privatekey":"SECRET","nested":{"key":"also-secret","keep":"v"},"list":[{"key":"x"}]}`)
	out := sanitizeBody(raw, 0, redactSet("privatekey", "key"))

	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("output is not valid JSON: %v (%s)", err, out)
	}
	if got["privatekey"] != "[REDACTED]" {
		t.Errorf("privatekey = %v, want [REDACTED]", got["privatekey"])
	}
	if got["name"] != "k" {
		t.Errorf("name = %v, want k (non-sensitive field must survive)", got["name"])
	}
	nested := got["nested"].(map[string]any)
	if nested["key"] != "[REDACTED]" {
		t.Errorf("nested.key = %v, want [REDACTED]", nested["key"])
	}
	if nested["keep"] != "v" {
		t.Errorf("nested.keep = %v, want v", nested["keep"])
	}
	list := got["list"].([]any)
	if list[0].(map[string]any)["key"] != "[REDACTED]" {
		t.Errorf("list[0].key not redacted: %v", list[0])
	}
}

func TestSanitizeBodyCaseInsensitive(t *testing.T) {
	out := sanitizeBody([]byte(`{"PrivateKey":"x"}`), 0, redactSet("privatekey"))
	var got map[string]any
	_ = json.Unmarshal(out, &got)
	if got["PrivateKey"] != "[REDACTED]" {
		t.Errorf("PrivateKey = %v, want [REDACTED] (case-insensitive)", got["PrivateKey"])
	}
}

func TestSanitizeBodyTruncates(t *testing.T) {
	raw := []byte(`{"data":"` + strings.Repeat("x", 100) + `"}`)
	out := sanitizeBody(raw, 32, nil)

	// Truncated output must be a valid JSON string carrying the marker.
	var s string
	if err := json.Unmarshal(out, &s); err != nil {
		t.Fatalf("truncated output must be a JSON string, got %s: %v", out, err)
	}
	if !strings.HasSuffix(s, "...(truncated)") {
		t.Errorf("truncated body missing marker: %q", s)
	}
	if len(s) > 32+len("...(truncated)") {
		t.Errorf("truncated body too long: %d", len(s))
	}
}

func TestSanitizeBodyNonJSON(t *testing.T) {
	out := sanitizeBody([]byte("not json at all"), 0, redactSet("key"))
	var s string
	if err := json.Unmarshal(out, &s); err != nil {
		t.Fatalf("non-JSON body must be embedded as a JSON string, got %s: %v", out, err)
	}
	if s != "not json at all" {
		t.Errorf("non-JSON body = %q", s)
	}
}

func TestSanitizeBodyNoRedactKeepsInlineJSON(t *testing.T) {
	raw := []byte(`{"a":1,"b":2}`)
	out := sanitizeBody(raw, 0, nil)
	if string(out) != string(raw) {
		t.Errorf("with no redaction the JSON should be embedded verbatim: got %s", out)
	}
}

func TestSanitizeBodyEmpty(t *testing.T) {
	if out := sanitizeBody(nil, 0, redactSet("key")); out != nil {
		t.Errorf("empty body should return nil, got %s", out)
	}
}
