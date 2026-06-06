package sd

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/peios/libp-go/wire"
	uapi "github.com/peios/pkm/uapi/go"
)

// SetCAAP installs a central access policy (CAAP): spec — a
// msgpack-encoded policy spec, per the KACS UAPI — is registered under
// the identifying policy SID. It requires the SeTcbPrivilege.
func SetCAAP(policySID wire.SID, spec []byte) error {
	sid := policySID.Bytes()
	var sidPtr, specPtr unsafe.Pointer
	if len(sid) > 0 {
		sidPtr = unsafe.Pointer(&sid[0])
	}
	if len(spec) > 0 {
		specPtr = unsafe.Pointer(&spec[0])
	}
	_, err := retry(func() (uintptr, syscall.Errno) {
		_, _, e := syscall.Syscall6(uapi.SYS_KACS_SET_CAAP,
			uintptr(sidPtr), uintptr(len(sid)),
			uintptr(specPtr), uintptr(len(spec)), 0, 0)
		return 0, e
	})
	runtime.KeepAlive(sid)
	runtime.KeepAlive(spec)
	if err != nil {
		return fmt.Errorf("libp/sd: set caap: %w", err)
	}
	return nil
}
