package facts

import (
	"reflect"
	"testing"
)

// Real's shape, measured: three floats under 1m/5m/15m.
func TestParseLoadavg(t *testing.T) {
	got := parseLoadavg(" 8.62 9.31 8.88 ")
	want := map[string]any{"1m": 8.62, "5m": 9.31, "15m": 8.88}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
	// /proc/loadavg's own spelling, which is what Linux supplies.
	if got := parseLoadavg("0.52 0.58 0.59"); got["1m"] != 0.52 || got["15m"] != 0.59 {
		t.Fatalf("got %#v", got)
	}
	for _, bad := range []string{"", "1.0 2.0", "a b c", "1 2 3 4"} {
		if got := parseLoadavg(bad); got != nil {
			t.Errorf("parseLoadavg(%q) = %#v, want nil", bad, got)
		}
	}
}

func TestResolverFacts(t *testing.T) {
	got := resolverFacts(map[string]string{
		"dns_search":      "example.org example.net ",
		"dns_nameservers": "203.0.113.53 203.0.113.54 ",
	})
	want := map[string]any{
		"search":      []any{"example.org", "example.net"},
		"nameservers": []any{"203.0.113.53", "203.0.113.54"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
	// Neither declared: absent, not an empty dict. Real was measured
	// WITH a resolver configured; what it reports without one was not,
	// so nothing is asserted about that case by inventing a value.
	if got := resolverFacts(map[string]string{}); got != nil {
		t.Fatalf("got %#v, want nil", got)
	}
	// One without the other still reports what it has.
	got = resolverFacts(map[string]string{"dns_nameservers": "203.0.113.53 "})
	if _, ok := got["search"]; ok {
		t.Errorf("search present with none declared: %#v", got)
	}
	if !reflect.DeepEqual(got["nameservers"], []any{"203.0.113.53"}) {
		t.Errorf("nameservers = %#v", got["nameservers"])
	}
}

// The two fields of a .pub file become two facts, and real names them
// so that the blob keeps the plain name and the algorithm gets the
// longer one. Values here are fabricated: a host's real keys are not
// something to put in a repository.
func TestSSHHostKeyFactNames(t *testing.T) {
	out := assemble(map[string]string{
		"sshkey_ed25519_type":   "ssh-ed25519",
		"sshkey_ed25519_public": "AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE",
		"sshkey_rsa_type":       "ssh-rsa",
		"sshkey_rsa_public":     "AAAAB3NzaC1yc2EAAAADAQABAAABgQEXAMPLE",
	}, "", nil)
	for key, want := range map[string]any{
		"ssh_host_key_ed25519_public":         "AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE",
		"ssh_host_key_ed25519_public_keytype": "ssh-ed25519",
		"ssh_host_key_rsa_public":             "AAAAB3NzaC1yc2EAAAADAQABAAABgQEXAMPLE",
		"ssh_host_key_rsa_public_keytype":     "ssh-rsa",
	} {
		if out[key] != want {
			t.Errorf("%s = %#v, want %#v", key, out[key], want)
		}
	}
	// A key type the host does not have produces no fact at all.
	for _, absent := range []string{"ssh_host_key_dsa_public", "ssh_host_key_ecdsa_public_keytype"} {
		if _, ok := out[absent]; ok {
			t.Errorf("%s present although the host has no such key", absent)
		}
	}
}

// module_setup says the setup module ran, which is how a playbook
// tells gathered facts from gather_facts: false. Real sets it
// unconditionally, so it is there even for a host that answered
// almost nothing.
func TestModuleSetupIsAlwaysReported(t *testing.T) {
	if out := assemble(map[string]string{}, "", nil); out["module_setup"] != true {
		t.Fatalf("module_setup = %#v, want true", out["module_setup"])
	}
}

func TestGecosAndIPv6List(t *testing.T) {
	out := assemble(map[string]string{
		"user_gecos":   "A Person",
		"net_all_ipv6": "fe80::dead:beef%en0 2001:db8::1 ",
	}, "", nil)
	if out["user_gecos"] != "A Person" {
		t.Errorf("user_gecos = %#v", out["user_gecos"])
	}
	if want := []any{"fe80::dead:beef%en0", "2001:db8::1"}; !reflect.DeepEqual(out["all_ipv6_addresses"], want) {
		t.Errorf("all_ipv6_addresses = %#v, want %#v", out["all_ipv6_addresses"], want)
	}
	// An empty value reports nothing rather than an empty list.
	bare := assemble(map[string]string{}, "", nil)
	if _, ok := bare["user_gecos"]; ok {
		t.Error("user_gecos present with none reported")
	}
	if _, ok := bare["all_ipv6_addresses"]; ok {
		t.Error("all_ipv6_addresses present with none reported")
	}
}
