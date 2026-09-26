package facts

import (
	"encoding/json"
	"fmt"
	"strings"
)

// parseLocalFacts turns the probe's facts.d section into real's
// ansible_local: one entry per *.fact file, keyed by the filename
// without its extension.
//
// Real's rules, read from ansible/module_utils/facts/system/local.py
// and checked against a run with four files:
//
//   - an executable file is RUN and its stdout used; any other file is
//     read;
//   - the content is parsed as JSON first, and as an INI file if that
//     fails -- so every INI value is a STRING, even "3";
//   - content that is neither becomes the ERROR TEXT ITSELF, as the
//     fact's value, rather than being dropped. A playbook reading
//     ansible_local.broken gets a sentence explaining why.
//
// The probe has already done the running and reading; the shape it
// emits is
//
//	FACTD <name>
//	FACTC <line>
//	FACTZ
func parseLocalFacts(section string) map[string]any {
	out := map[string]any{}
	if strings.TrimSpace(section) == "" {
		return out
	}
	// The first name lost its "FACTD " marker to the caller's Cut.
	var name string
	var body []string
	flush := func() {
		if name == "" {
			return
		}
		out[name] = parseFactContent(name, strings.Join(body, "\n"))
		name, body = "", nil
	}
	first := true
	for _, line := range strings.Split(section, "\n") {
		switch {
		case first:
			name = strings.TrimSpace(line)
			first = false
		case strings.HasPrefix(line, "FACTD "):
			flush()
			name = strings.TrimSpace(strings.TrimPrefix(line, "FACTD "))
		case line == "FACTZ":
			flush()
		case strings.HasPrefix(line, "FACTC "):
			body = append(body, strings.TrimPrefix(line, "FACTC "))
		}
	}
	flush()
	return out
}

// parseFactContent is JSON, then INI, then the error text.
func parseFactContent(name, content string) any {
	var v any
	if err := json.Unmarshal([]byte(content), &v); err == nil {
		return v
	}
	if sections, ok := parseFactINI(content); ok {
		return sections
	}
	// Real puts the explanation where the fact would have been. The
	// path it names is the file's, which this side does not carry, so
	// the name is used -- the sentence is real's, the subject is what
	// is available.
	return fmt.Sprintf("error loading facts as JSON or ini - please check content: %s.fact", name)
}

// parseFactINI reads the [section] key = value form, reporting whether
// the content looked like one at all. Every value is a string, which
// is what configparser yields and what real therefore reports.
func parseFactINI(content string) (map[string]any, bool) {
	out := map[string]any{}
	var current map[string]any
	sawSection := false
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			name := strings.TrimSpace(line[1 : len(line)-1])
			current = map[string]any{}
			out[name] = current
			sawSection = true
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || current == nil {
			// A key outside any section, or a line that is not a
			// key at all: configparser refuses the whole file, and so
			// does this.
			return nil, false
		}
		current[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out, sawSection
}

// shellQuoteSingle wraps a path for the probe's own shell. The path
// comes from a playbook, so it is not trusted to be free of quotes.
func shellQuoteSingle(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
