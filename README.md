# facts

Fact gathering (the 'setup' module equivalent), pure Go CGO=0.

Part of [go-ansible](https://github.com/go-ansible) — a pure-Go (CGO=0),
functional-parity port of [Ansible](https://www.ansible.com/).

[![CI](https://github.com/go-ansible/facts/actions/workflows/ci.yml/badge.svg)](https://github.com/go-ansible/facts/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/go-ansible/facts.svg)](https://pkg.go.dev/github.com/go-ansible/facts)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue.svg)](LICENSE)

## Usage

```go
data, err := facts.Gather(ctx, conn) // conn: a github.com/go-remoteexec/transport.Connection

os := data["ansible_distribution"]     // e.g. "Ubuntu"
fam := data["ansible_os_family"]       // e.g. "Debian"
```

`Gather` collects the whole `ansible_facts`/`ansible_*` set in one shell round
trip to the target — no Python `setup` module, no per-fact command.
