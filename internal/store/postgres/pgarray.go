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
	elems, err := parseArrayElements(inner)
	if err != nil {
		return err
	}
	*a = elems
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

func parseArrayElements(s string) ([]string, error) {
	var result []string
	var current strings.Builder
	inQuote := false
	escaped := false
	quoted := false // whether the current element contained a quoted section

	flush := func() error {
		val := current.String()
		if !quoted {
			// PostgreSQL trims surrounding whitespace on unquoted elements, and
			// an unquoted NULL denotes a SQL NULL — unsupported by these NOT NULL
			// columns (roles, allowed_cidrs).
			val = strings.TrimSpace(val)
			if strings.EqualFold(val, "NULL") {
				return fmt.Errorf("pgarray: NULL array elements are not supported")
			}
		}
		result = append(result, val)
		current.Reset()
		quoted = false
		return nil
	}

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
			quoted = true
		case c == ',' && !inQuote:
			if err := flush(); err != nil {
				return nil, err
			}
		default:
			current.WriteByte(c)
		}
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return result, nil
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
