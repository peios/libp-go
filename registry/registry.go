// Package registry is the libp interface to LCS — the Layered
// Configuration Subsystem, PSD-005 — the Peios registry: a hierarchy of
// keys holding typed values, reached through custom syscalls (NOT the
// VFS). It is the Go counterpart of the libp-rs libp-registry crate, and
// completes libp-go's Tier-1 coverage alongside token, sd, files, and
// event.
//
// The shape:
//
//   - Open / Create / Begin / Transact — package functions, the entry
//     points (these syscalls hang off no handle).
//   - Key        — an owned key fd, closed by Close. Reads sit here and
//     always return the *effective* value resolved across the whole layer
//     stack, reporting which layer won.
//   - LayerWrite — writes flow through a layer view: Key.Base (the base
//     layer, the easy default) or Key.Layer(name). Layers are first-class;
//     base is just the null layer.
//   - Value      — a typed registry value (DWORD, QWORD, SZ, …).
//   - Transaction / Txn — atomic multi-op transactions. The closure form
//     Transact(func(*Txn) error) commits on a nil return and aborts
//     otherwise; the Begin handle is there for manual control.
//   - registry/layers — a first-class layer-management subpackage (create
//     / list / set precedence / enable / delete).
//
// # Value encoding
//
// LCS treats value data as an opaque typed blob — it stores the type tag
// and returns it on read but never interprets the payload (except
// REG_LINK on symlink keys; §2.5). The byte encoding of the string and
// integer types is therefore a libp convention, chosen to match the rest
// of Peios: string values (SZ / EXPAND_SZ / LINK / MULTI_SZ) are UTF-8,
// NUL-terminated — NOT Windows UTF-16; DWORD is 4 bytes little-endian,
// QWORD 8 bytes little-endian, DWORD_BIG_ENDIAN big-endian. This matches
// the libp-rs crate byte-for-byte. See Value.
//
// It is a libp-tier package — an idiomatic Go surface over the generated
// uapi binding. See libp-design.md and libp-map.md.
package registry

import (
	"fmt"
	"syscall"

	"github.com/peios/libp-go/internal/sys"
)

// Key is an owned handle to an LCS registry key. It wraps a kernel file
// descriptor; call Close when finished with it.
type Key struct {
	fd int
}

// Open opens an existing registry key by absolute path.
//
// path is hive-rooted (e.g. `Machine\Software\Acme`); the kernel accepts
// and normalises forward slashes, and rewrites a leading `CurrentUser\`
// to the caller's per-user hive. It fails with ENOENT if the key does not
// exist after layer resolution, or EACCES if access is not granted.
func Open(path string, access Access) (*Key, error) {
	return openAt(parentNone, path, access, 0)
}

// openAt opens path relative to parentFD (parentNone for an absolute
// path). It backs Open and Key.OpenSubkey.
func openAt(parentFD int, path string, access Access, flags uint32) (*Key, error) {
	cpath, err := syscall.BytePtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("libp/registry: open %q: invalid path: %w", path, err)
	}
	r, err := sys.Retry(func() (uintptr, syscall.Errno) {
		return openKey(parentFD, cpath, access.bits(), flags)
	})
	if err != nil {
		return nil, fmt.Errorf("libp/registry: open %q: %w", path, err)
	}
	return &Key{fd: int(r)}, nil
}

// FD returns the underlying kernel file descriptor, valid until Close.
func (k *Key) FD() int { return k.fd }

// Close releases the key handle. It is safe to call more than once.
func (k *Key) Close() error {
	if k.fd < 0 {
		return nil
	}
	err := syscall.Close(k.fd)
	k.fd = -1
	if err != nil {
		return fmt.Errorf("libp/registry: close: %w", err)
	}
	return nil
}

// OpenSubkey opens a subkey by a path relative to this key.
func (k *Key) OpenSubkey(path string, access Access) (*Key, error) {
	return openAt(k.fd, path, access, 0)
}

// CreateSubkey starts a create-or-open for a subkey by a path relative to
// this key. Configure the returned builder, then call Call.
func (k *Key) CreateSubkey(path string) *CreateOptions {
	return createAt(k.fd, path)
}

// Base returns a write view targeting the base layer — the easy default
// for ordinary writes.
func (k *Key) Base() *LayerWrite {
	return newLayerWrite(k, "", noTxn)
}

// Layer returns a write view targeting the named layer.
func (k *Key) Layer(name string) *LayerWrite {
	return newLayerWrite(k, name, noTxn)
}
