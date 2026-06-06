// Package token is the libp interface to KACS tokens — the kernel
// objects that carry a subject's security identity: SIDs, privileges,
// session, integrity level, impersonation state.
//
// It is a libp-tier package — an idiomatic Go surface over the
// generated uapi binding. See libp-design.md and libp-map.md.
package token

import (
	"fmt"
	"syscall"
	"unsafe"

	"github.com/peios/libp-go/internal/sys"
	uapi "github.com/peios/pkm/uapi/go"
)

// Access is a KACS token-handle access mask — the set of rights a Token
// handle is opened with. Values combine with bitwise OR.
type Access uint32

// Token-handle access rights, from pkm <pkm/token.h> via the
// github.com/peios/pkm/uapi/go binding.
const (
	AssignPrimary    Access = uapi.KACS_TOKEN_ASSIGN_PRIMARY
	Duplicate        Access = uapi.KACS_TOKEN_DUPLICATE
	Impersonate      Access = uapi.KACS_TOKEN_IMPERSONATE
	Query            Access = uapi.KACS_TOKEN_QUERY
	QuerySource      Access = uapi.KACS_TOKEN_QUERY_SOURCE
	AdjustPrivileges Access = uapi.KACS_TOKEN_ADJUST_PRIVS
	AdjustGroups     Access = uapi.KACS_TOKEN_ADJUST_GROUPS
	AdjustDefault    Access = uapi.KACS_TOKEN_ADJUST_DEFAULT
	AdjustSessionID  Access = uapi.KACS_TOKEN_ADJUST_SESSIONID
	AllAccess        Access = uapi.KACS_TOKEN_ALL_ACCESS
)

// OpenFlags modifies a self-token open. The zero value opens the
// effective (impersonation-aware) token.
type OpenFlags uint32

// OpenReal opens the caller's real (primary) token rather than its
// effective token, when the two differ under an active impersonation.
const OpenReal OpenFlags = uapi.KACS_TOKEN_OPEN_REAL

// Token is an open handle to a KACS token. It wraps a kernel file
// descriptor; call Close when finished with it.
type Token struct {
	fd int
}

// OpenSelf opens a handle to the calling task's token. With flags 0 it
// opens the effective token (the identity the task is acting under,
// including any active impersonation); with OpenReal it opens the
// primary token.
//
// access is the set of rights the handle is opened with; the kernel
// rejects a zero mask with EINVAL.
func OpenSelf(flags OpenFlags, access Access) (*Token, error) {
	r, err := retry(func() (uintptr, syscall.Errno) {
		r1, _, e := syscall.Syscall(uapi.SYS_KACS_OPEN_SELF_TOKEN,
			uintptr(flags), uintptr(access), 0)
		return r1, e
	})
	if err != nil {
		return nil, fmt.Errorf("libp/token: open self token: %w", err)
	}
	return &Token{fd: int(r)}, nil
}

// OpenProcess opens the token of the process referenced by pidfd.
func OpenProcess(pidfd int, access Access) (*Token, error) {
	r, err := retry(func() (uintptr, syscall.Errno) {
		r1, _, e := syscall.Syscall(uapi.SYS_KACS_OPEN_PROCESS_TOKEN,
			uintptr(pidfd), uintptr(access), 0)
		return r1, e
	})
	if err != nil {
		return nil, fmt.Errorf("libp/token: open process token: %w", err)
	}
	return &Token{fd: int(r)}, nil
}

// OpenThread opens the impersonation token of thread tid in the process
// referenced by pidfd.
func OpenThread(pidfd, tid int, access Access) (*Token, error) {
	r, err := retry(func() (uintptr, syscall.Errno) {
		r1, _, e := syscall.Syscall(uapi.SYS_KACS_OPEN_THREAD_TOKEN,
			uintptr(pidfd), uintptr(tid), uintptr(access))
		return r1, e
	})
	if err != nil {
		return nil, fmt.Errorf("libp/token: open thread token: %w", err)
	}
	return &Token{fd: int(r)}, nil
}

// OpenPeer opens the token captured for the peer of a connected AF_UNIX
// socket.
func OpenPeer(sockfd int) (*Token, error) {
	r, err := retry(func() (uintptr, syscall.Errno) {
		r1, _, e := syscall.Syscall(uapi.SYS_KACS_OPEN_PEER_TOKEN,
			uintptr(sockfd), 0, 0)
		return r1, e
	})
	if err != nil {
		return nil, fmt.Errorf("libp/token: open peer token: %w", err)
	}
	return &Token{fd: int(r)}, nil
}

// Create builds a new token from a msgpack-encoded creation spec (per
// the KACS UAPI).
func Create(spec []byte) (*Token, error) {
	var ptr unsafe.Pointer
	if len(spec) > 0 {
		ptr = unsafe.Pointer(&spec[0])
	}
	r, err := retry(func() (uintptr, syscall.Errno) {
		r1, _, e := syscall.Syscall(uapi.SYS_KACS_CREATE_TOKEN,
			uintptr(ptr), uintptr(len(spec)), 0)
		return r1, e
	})
	if err != nil {
		return nil, fmt.Errorf("libp/token: create token: %w", err)
	}
	return &Token{fd: int(r)}, nil
}

// FD returns the underlying kernel file descriptor, valid until Close.
func (t *Token) FD() int { return t.fd }

// Close releases the token handle. It is safe to call more than once.
func (t *Token) Close() error {
	if t.fd < 0 {
		return nil
	}
	err := syscall.Close(t.fd)
	t.fd = -1
	if err != nil {
		return fmt.Errorf("libp/token: close: %w", err)
	}
	return nil
}

// retry runs a syscall closure, retrying transparently on EINTR, and
// maps a nonzero kernel errno to an errno.Errno. The closure performs
// the syscall itself, so any unsafe.Pointer conversion stays inside the
// syscall.Syscall argument list, as the runtime requires.
var retry = sys.Retry
