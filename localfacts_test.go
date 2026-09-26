package facts

import (
	"reflect"
	"testing"
)

// The four shapes, captured from ansible-core 2.21.4 running against a
// fact_path holding a JSON file, an INI file, an executable script and
// a file that is neither.
func TestParseLocalFacts(t *testing.T) {
	section := "j /tmp/factsd/j.fact\n" +
		"FACTC {\"answer\": 42, \"nested\": {\"k\": \"v\"}}\n" +
		"FACTZ\n" +
		"FACTD i /tmp/factsd/i.fact\n" +
		"FACTC [general]\n" +
		"FACTC name = widget\n" +
		"FACTC count = 3\n" +
		"FACTC \n" +
		"FACTC [other]\n" +
		"FACTC flag = yes\n" +
		"FACTZ\n" +
		"FACTD bad /tmp/factsd/bad.fact\n" +
		"FACTC not json and not ini at all\n" +
		"FACTZ\n"

	got := parseLocalFacts(section)
	want := map[string]any{
		"j": map[string]any{"answer": float64(42), "nested": map[string]any{"k": "v"}},
		// Every INI value is a STRING -- "3" and "yes", not 3 and true
		// -- because configparser yields strings and real reports what
		// it yields.
		"i": map[string]any{
			"general": map[string]any{"name": "widget", "count": "3"},
			"other":   map[string]any{"flag": "yes"},
		},
		// The error text IS the fact's value, naming the file, so a
		// playbook reading it learns why rather than finding nothing.
		"bad": "error loading facts as JSON or ini - please check content: /tmp/factsd/bad.fact",
	}
	if !reflect.DeepEqual(got, want) {
		for _, k := range []string{"j", "i", "bad"} {
			if !reflect.DeepEqual(got[k], want[k]) {
				t.Errorf("%s =\n  %#v\nwant\n  %#v", k, got[k], want[k])
			}
		}
	}
}

// No directory, or an empty one: an empty dict, never a missing key.
// Real always reports ansible_local.
func TestParseLocalFactsEmpty(t *testing.T) {
	for _, in := range []string{"", "\n", "   "} {
		got := parseLocalFacts(in)
		if got == nil || len(got) != 0 {
			t.Errorf("parseLocalFacts(%q) = %#v, want an empty map", in, got)
		}
	}
}

// JSON wins over INI: a file that parses as both is JSON.
func TestParseFactContentPrefersJSON(t *testing.T) {
	if got := parseFactContent("/x.fact", `{"a": 1}`); !reflect.DeepEqual(got, map[string]any{"a": float64(1)}) {
		t.Errorf("got %#v", got)
	}
	// A key outside any section is not an INI file; configparser
	// refuses it, so the value becomes the error text.
	got := parseFactContent("/x.fact", "loose = value\n")
	if s, ok := got.(string); !ok || s == "" {
		t.Errorf("got %#v, want the error text", got)
	}
}

func TestShellQuoteSingle(t *testing.T) {
	// The path comes from a playbook, so it is not trusted to be free
	// of quotes.
	if got := shellQuoteSingle(`/a b/c'd`); got != `'/a b/c'\''d'` {
		t.Errorf("got %s", got)
	}
}
