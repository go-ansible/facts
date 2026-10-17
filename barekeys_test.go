package facts

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	remoteexec "github.com/go-remoteexec/transport"
)

// Every key this package returns is BARE -- "system", not
// "ansible_system" -- because vars.InjectFacts prefixes all of them on
// the way into a play's scope. The Gather doc has said so all along;
// nothing enforced it, and one key did not comply.
//
// "ansible_local" was that key. InjectFacts turned it into
// ansible_ansible_local, so `fact_path` collected its *.fact files
// correctly and published them under a name no playbook would ever
// ask for: `ansible_local` was undefined, and `ansible -m setup`
// emitted ansible_ansible_local too. Measured against real
// ansible-core 2.21.4, which gives ansible_local.demo.general.answer
// == "42" for a facts.d/demo.fact holding `[general]` / `answer = 42`.
//
// This is the contract rather than that one key, so the next addition
// cannot repeat it.
func TestEveryFactKeyIsBare(t *testing.T) {
	f, err := Gather(context.Background(), remoteexec.NewLocal())
	if err != nil {
		t.Fatal(err)
	}
	if len(f) < 5 {
		t.Fatalf("Gather returned only %d keys, which cannot be right: "+
			"this test would pass on an empty map", len(f))
	}
	for k := range f {
		if strings.HasPrefix(k, "ansible_") {
			t.Errorf("fact key %q carries the ansible_ prefix; vars.InjectFacts adds it, "+
				"so this would be published as ansible_%s", k, k)
		}
	}
}

// And the local facts specifically arrive under "local", so that a
// consumer prefixing once lands on real's ansible_local.
func TestLocalFactsLandUnderTheBareKey(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "demo.fact"), []byte("[general]\nanswer = 42\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := GatherWith(context.Background(), remoteexec.NewLocal(), Options{FactPath: dir})
	if err != nil {
		t.Fatal(err)
	}
	local, ok := f["local"].(map[string]any)
	if !ok {
		var present []string
		for k := range f {
			present = append(present, k)
		}
		sort.Strings(present)
		t.Fatalf(`f["local"] is %T, want map[string]any — keys present: %v`, f["local"], present)
	}
	demo, ok := local["demo"].(map[string]any)
	if !ok {
		t.Fatalf(`local["demo"] is %T, want map[string]any`, local["demo"])
	}
	general, ok := demo["general"].(map[string]any)
	if !ok {
		t.Fatalf(`demo["general"] is %T, want map[string]any`, demo["general"])
	}
	if got := general["answer"]; got != "42" {
		t.Errorf(`local.demo.general.answer = %#v, want "42"`, got)
	}
}
