package token

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"

	uapi "github.com/peios/pkm/uapi/go"
)

// revert drops the calling thread's impersonation, restoring its real
// token. It is unexported by design: impersonation is reachable only
// through the closure-scoped Impersonate / ImpersonatePeer, and revert
// is their cleanup step (see libp-design.md §2.5).
func revert() error {
	_, err := retry(func() (uintptr, syscall.Errno) {
		_, _, e := syscall.Syscall(uapi.SYS_KACS_REVERT, 0, 0, 0)
		return 0, e
	})
	return err
}

// impersonateScoped runs fn with an impersonation in effect, pinned to a
// single OS thread for safety: Go migrates goroutines across threads,
// and KACS impersonation is per-thread, so a set-and-return primitive
// would leak the impersonation onto the wrong thread.
//
// set establishes the impersonation and runs on the locked thread. If
// the closing revert fails, the thread is left locked so it dies with
// this goroutine rather than rejoining the pool still impersonating.
func impersonateScoped(set, fn func() error) (err error) {
	runtime.LockOSThread()
	if e := set(); e != nil {
		runtime.UnlockOSThread()
		return e
	}
	defer func() {
		if e := revert(); e != nil {
			err = errors.Join(err, fmt.Errorf("libp/token: revert: %w", e))
			return
		}
		runtime.UnlockOSThread()
	}()
	return fn()
}

// Impersonate runs fn with the calling thread's effective token set to
// this token, reverting when fn returns.
//
// The impersonation is scoped to the current OS thread for the duration
// of fn. Goroutines that fn starts run on other threads and are NOT
// impersonated — the impersonated work must be done inline in fn.
func (t *Token) Impersonate(fn func() error) error {
	return impersonateScoped(func() error {
		if err := t.ioctl(uapi.KACS_IOC_IMPERSONATE, nil); err != nil {
			return fmt.Errorf("libp/token: impersonate: %w", err)
		}
		return nil
	}, fn)
}

// ImpersonatePeer runs fn while impersonating the peer of a connected
// AF_UNIX socket. The same thread-scoping contract as Impersonate
// applies — see that method.
func ImpersonatePeer(sockfd int, fn func() error) error {
	return impersonateScoped(func() error {
		_, err := retry(func() (uintptr, syscall.Errno) {
			_, _, e := syscall.Syscall(uapi.SYS_KACS_IMPERSONATE_PEER,
				uintptr(sockfd), 0, 0)
			return 0, e
		})
		if err != nil {
			return fmt.Errorf("libp/token: impersonate peer: %w", err)
		}
		return nil
	}, fn)
}

// SetImpersonationLevel sets the impersonation level the peer of a
// connected AF_UNIX socket is granted when it impersonates this side.
func SetImpersonationLevel(sockfd int, level ImpersonationLevel) error {
	_, err := retry(func() (uintptr, syscall.Errno) {
		_, _, e := syscall.Syscall(uapi.SYS_KACS_SET_IMPERSONATION_LEVEL,
			uintptr(sockfd), uintptr(level), 0)
		return 0, e
	})
	if err != nil {
		return fmt.Errorf("libp/token: set impersonation level: %w", err)
	}
	return nil
}
