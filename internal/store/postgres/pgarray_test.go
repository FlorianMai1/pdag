package postgres

import (
	"database/sql/driver"
	"reflect"
	"testing"
)

func TestTextArrayScan(t *testing.T) {
	tests := []struct {
		name    string
		input   any
		want    TextArray
		wantErr bool
	}{
		{"nil", nil, nil, false},
		{"empty", "{}", TextArray{}, false},
		{"single", "{admin}", TextArray{"admin"}, false},
		{"multiple", "{admin,read_zones,viewer}", TextArray{"admin", "read_zones", "viewer"}, false},
		{"quoted with comma", `{"hello,world",simple}`, TextArray{"hello,world", "simple"}, false},
		{"quoted with spaces", `{"hello world",nospace}`, TextArray{"hello world", "nospace"}, false},
		{"escaped quote", `{"say \"hi\"",plain}`, TextArray{`say "hi"`, "plain"}, false},
		{"escaped backslash", `{"back\\slash",plain}`, TextArray{`back\slash`, "plain"}, false},
		{"bytes input", []byte("{a,b,c}"), TextArray{"a", "b", "c"}, false},
		{"invalid type", 42, nil, true},
		{"invalid format", "not-an-array", nil, true},
		{"missing braces", "a,b,c", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var a TextArray
			err := a.Scan(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Scan() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && !reflect.DeepEqual(a, tt.want) {
				t.Errorf("Scan() = %v, want %v", a, tt.want)
			}
		})
	}
}

func TestTextArrayValue(t *testing.T) {
	tests := []struct {
		name string
		arr  TextArray
		want driver.Value
	}{
		{"nil", nil, nil},
		{"empty", TextArray{}, "{}"},
		{"single", TextArray{"admin"}, "{admin}"},
		{"multiple", TextArray{"admin", "read_zones"}, "{admin,read_zones}"},
		{"needs quoting - comma", TextArray{"a,b", "c"}, `{"a,b",c}`},
		{"needs quoting - space", TextArray{"hello world"}, `{"hello world"}`},
		{"needs quoting - empty string", TextArray{""}, `{""}`},
		{"needs quoting - braces", TextArray{"{x}"}, `{"{x}"}`},
		{"needs escaping - quote", TextArray{`say "hi"`}, `{"say \"hi\""}`},
		{"needs escaping - backslash", TextArray{`back\slash`}, `{"back\\slash"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.arr.Value()
			if err != nil {
				t.Fatalf("Value() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("Value() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTextArrayRoundtrip(t *testing.T) {
	original := TextArray{"admin", "read_zones", "hello world", `say "hi"`, "a,b"}

	val, err := original.Value()
	if err != nil {
		t.Fatal(err)
	}

	var restored TextArray
	if err := restored.Scan(val); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(original, restored) {
		t.Errorf("roundtrip failed: original=%v, restored=%v", original, restored)
	}
}
