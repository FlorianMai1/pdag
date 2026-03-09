package postgres

import (
	"database/sql/driver"
	"fmt"
	"strings"
)

// TextArray implements sql.Scanner and driver.Valuer for PostgreSQL text[] columns.
// This avoids depending on github.com/lib/pq just for array handling.
type TextArray []string

// Scan implements sql.Scanner for PostgreSQL text array literals like {a,b,c}.
func (a *TextArray) Scan(src any) error {
	if src == nil {
		*a = nil
		return nil
	}

	var s string
	switch v := src.(type) {
	case string:
		s = v
	case []byte:
		s = string(v)
	default:
		return fmt.Errorf("pgarray: cannot scan %T", src)
	}

	s = strings.TrimSpace(s)
	if s == "{}" {
		*a = []string{}
		return nil
	}
	if len(s) < 2 || s[0] != '{' || s[len(s)-1] != '}' {
		return fmt.Errorf("pgarray: invalid array literal: %q", s)
	}

	inner := s[1 : len(s)-1]
	*a = parseArrayElements(inner)
	return nil
}

// Value implements driver.Valuer for PostgreSQL text array literals.
func (a TextArray) Value() (driver.Value, error) {
	if a == nil {
		return nil, nil
	}
	elems := make([]string, len(a))
	for i, v := range a {
		elems[i] = quoteArrayElement(v)
	}
	return "{" + strings.Join(elems, ",") + "}", nil
}

func parseArrayElements(s string) []string {
	var result []string
	var current strings.Builder
	inQuote := false
	escaped := false

	for i := 0; i < len(s); i++ {
		c := s[i]
		if escaped {
			current.WriteByte(c)
			escaped = false
			continue
		}
		switch {
		case c == '\\':
			escaped = true
		case c == '"':
			inQuote = !inQuote
		case c == ',' && !inQuote:
			result = append(result, current.String())
			current.Reset()
		default:
			current.WriteByte(c)
		}
	}
	result = append(result, current.String())
	return result
}

func quoteArrayElement(s string) string {
	if s == "" || strings.ContainsAny(s, `{},"\`) || strings.ContainsAny(s, " \t\n") {
		var b strings.Builder
		b.WriteByte('"')
		for _, c := range s {
			if c == '"' || c == '\\' {
				b.WriteByte('\\')
			}
			b.WriteRune(c)
		}
		b.WriteByte('"')
		return b.String()
	}
	return s
}
