package token

import (
	"fmt"
	"syscall"
	"unsafe"

	uapi "github.com/peios/pkm/uapi/go"
)

// SessionID identifies a KACS session.
type SessionID uint64

// CreateSession creates a new session from a msgpack-encoded spec and
// returns its id.
func CreateSession(spec []byte) (SessionID, error) {
	var ptr unsafe.Pointer
	if len(spec) > 0 {
		ptr = unsafe.Pointer(&spec[0])
	}
	r, err := retry(func() (uintptr, syscall.Errno) {
		r1, _, e := syscall.Syscall(uapi.SYS_KACS_CREATE_SESSION,
			uintptr(ptr), uintptr(len(spec)), 0)
		return r1, e
	})
	if err != nil {
		return 0, fmt.Errorf("libp/token: create session: %w", err)
	}
	return SessionID(r), nil
}

// DestroyEmptySession destroys a session that has no remaining
// occupants. It fails with EBUSY if the session is not empty.
func DestroyEmptySession(id SessionID) error {
	_, err := retry(func() (uintptr, syscall.Errno) {
		_, _, e := syscall.Syscall(uapi.SYS_KACS_DESTROY_EMPTY_SESSION,
			uintptr(id), 0, 0)
		return 0, e
	})
	if err != nil {
		return fmt.Errorf("libp/token: destroy empty session: %w", err)
	}
	return nil
}

// SetPSB sets the Process Security Block mitigation flags for the
// process referenced by pidfd.
func SetPSB(pidfd int, mitigations uint32) error {
	_, err := retry(func() (uintptr, syscall.Errno) {
		_, _, e := syscall.Syscall(uapi.SYS_KACS_SET_PSB,
			uintptr(pidfd), uintptr(mitigations), 0)
		return 0, e
	})
	if err != nil {
		return fmt.Errorf("libp/token: set psb: %w", err)
	}
	return nil
}
