// Package sys holds syscall plumbing shared by the libp-go domain
// packages. It is internal — not part of libp's public surface.
package sys

import (
	"syscall"

	"github.com/peios/libp-go/errno"
)

// Retry runs a syscall closure, retrying transparently on EINTR, and
// maps a nonzero kernel errno to an errno.Errno. The closure must
// perform the syscall itself, so any unsafe.Pointer conversion stays
// inside the syscall call, as the runtime requires.
func Retry(call func() (uintptr, syscall.Errno)) (uintptr, error) {
	for {
		r, e := call()
		switch e {
		case 0:
			return r, nil
		case syscall.EINTR:
			continue
		default:
			return r, errno.Errno(e)
		}
	}
}
