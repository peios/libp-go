# libp-go

The Go implementation of **libp**, the Peios kernel-interface library.

See [`../libp-design.md`](../libp-design.md) for the full design — what
libp is, the `uapi`/`libp` split, and the roadmap — and
[`../libp-map.md`](../libp-map.md) for the capability ledger.

## Status

Phase 2 — the vertical slice. The `token` package (`OpenSelf`/`Close`)
round-trips a real `kacs_open_self_token` syscall, proven on a booted
Peios VM. The `wire` codecs and the remaining domains (`sd`, `files`,
`event`) follow.

## Layout

- `token/` — KACS tokens (the `libp` tier)
- `errno/` — the typed kernel error number

The `uapi` tier — syscall numbers and ABI structs — is not in this repo:
it is the generated `github.com/peios/pkm/uapi/go` binding, published by
pkm and imported here. A local `replace` in `go.mod` points it at
`../pkm/uapi/go`.

## Building

CGO-free, static, Linux/amd64:

    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./...

Tests skip automatically when not run on a Peios kernel.
