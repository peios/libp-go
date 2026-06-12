package registry

import (
	"syscall"
	"unsafe"

	"github.com/peios/libp-go/internal/sys"
	uapi "github.com/peios/pkm/uapi/go"
)

// Raw LCS syscall and ioctl plumbing (PSD-005 §6). These wrappers are
// deliberately unexported: unlike the libp-rs crate's public `raw`
// module, Go discourages exposing an unsafe escape hatch, and every entry
// point here has a safe method above it. Request numbers and arg structs
// come from the generated uapi binding.

// parentNone is the parent_fd value for absolute (hive-rooted) path
// resolution; noTxn is the txn_fd sentinel meaning "no transaction".
const (
	parentNone = -1
	noTxn      = -1
)

// Probe-buffer sizing for the kernel's two-pass variable-length read ABI
// (§6.3): try a reasonable buffer, and on ERANGE regrow to the size the
// kernel reports and retry.
const (
	dataCapHint     = 256  // a value-data output buffer
	nameCapHint     = 64   // a name / layer-name output buffer
	sdCapHint       = 1024 // a security-descriptor output buffer
	maxProbeRetries = 4    // probe→regrow attempts before giving up
)

// --- Syscalls -------------------------------------------------------------

// openKey issues reg_open_key(parent_fd, path, desired_access, flags).
// path must be a NUL-terminated C string kept alive across the call by the
// caller. Returns the raw (r1, errno) for sys.Retry.
func openKey(parentFD int, path *byte, access, flags uint32) (uintptr, syscall.Errno) {
	r1, _, e := syscall.Syscall6(uapi.SYS_REG_OPEN_KEY,
		uintptr(parentFD),
		uintptr(unsafe.Pointer(path)),
		uintptr(access),
		uintptr(flags),
		0, 0)
	return r1, e
}

// createKey issues reg_create_key(&args). args' pointer fields must be
// kept alive across the call by the caller.
func createKey(args *uapi.Reg_create_key_args) (uintptr, syscall.Errno) {
	r1, _, e := syscall.Syscall(uapi.SYS_REG_CREATE_KEY,
		uintptr(unsafe.Pointer(args)), 0, 0)
	return r1, e
}

// beginTransaction issues reg_begin_transaction(); no arguments, no memory
// the kernel reads.
func beginTransaction() (uintptr, syscall.Errno) {
	r1, _, e := syscall.Syscall(uapi.SYS_REG_BEGIN_TRANSACTION, 0, 0, 0)
	return r1, e
}

// --- ioctl ---------------------------------------------------------------

// ioctl issues one ioctl against the key fd, retrying transparently on
// EINTR. arg points at the ioctl argument struct, or is nil for the
// argument-less ioctls (FLUSH). The caller keeps any buffers referenced
// by arg alive across the call.
func (k *Key) ioctl(request uintptr, arg unsafe.Pointer) error {
	_, err := sys.Retry(func() (uintptr, syscall.Errno) {
		_, _, e := syscall.Syscall(syscall.SYS_IOCTL,
			uintptr(k.fd), request, uintptr(arg))
		return 0, e
	})
	return err
}

// fdIoctl issues an argument-less or fd-targeting ioctl against an
// arbitrary fd (used for the transaction-fd ioctls COMMIT / TXN_STATUS).
func fdIoctl(fd int, request uintptr, arg unsafe.Pointer) error {
	_, err := sys.Retry(func() (uintptr, syscall.Errno) {
		_, _, e := syscall.Syscall(syscall.SYS_IOCTL,
			uintptr(fd), request, uintptr(arg))
		return 0, e
	})
	return err
}

// bytesPtr returns a pointer to the first byte of b, or nil for an empty
// slice — the (ptr, len) convention the kernel reads for non-terminated
// name / data / layer buffers. The caller keeps b alive across the call.
func bytesPtr(b []byte) unsafe.Pointer {
	if len(b) == 0 {
		return nil
	}
	return unsafe.Pointer(&b[0])
}

// layerBytes encodes an optional layer name as the byte slice an ioctl's
// (ptr, len) layer fields want. The empty string (the base layer) yields a
// nil slice — the null/zero default.
func layerBytes(layer string) []byte {
	if layer == "" {
		return nil
	}
	return []byte(layer)
}

// ptr is unsafe.Pointer under a short name, so the read/write files build
// args structs without importing unsafe themselves.
func ptr[T any](p *T) unsafe.Pointer { return unsafe.Pointer(p) }

// boolU8 maps a bool to the kernel's 0/1 byte form.
func boolU8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}
