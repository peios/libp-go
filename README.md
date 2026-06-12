# libp-go

The Go implementation of **libp**, the Peios kernel-interface library.

See [`../libp-design.md`](../libp-design.md) for the full design — what
libp is, the `uapi`/`libp` split, and the roadmap — and
[`../libp-map.md`](../libp-map.md) for the capability ledger.

## Status

The Tier-1 domains are in place: `token` (KACS tokens) round-trips a real
`kacs_open_self_token` syscall proven on a booted Peios VM, and `sd`,
`sddl`, `files`, `event`, and `registry` (the LCS registry) sit alongside
it over the `wire` codecs.

## Layout

- `token/` — KACS tokens (the `libp` tier)
- `sd/` — security descriptors, ACLs/ACEs, access checks
- `sddl/` — the SDDL text format
- `files/` — KACS files (the `NtCreateFile`-shaped open) and mount policy
- `event/` — KMES, the Kernel-Mediated Event Stream
- `registry/` — LCS, the Layered Configuration Subsystem (keys, typed
  values, layers, transactions, change watches); `registry/layers/` is
  the first-class layer-management subpackage
- `wire/` — hand-written on-wire codecs (SIDs, the KMES event header)
- `errno/` — the typed kernel error number

The `uapi` tier — syscall numbers and ABI structs — is not in this repo:
it is the generated `github.com/peios/pkm/uapi/go` binding, published by
pkm and imported here (pinned in `go.mod`).

## Building

CGO-free, static, Linux/amd64:

    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./...

Tests skip automatically when not run on a Peios kernel.
