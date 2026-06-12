package registry

import "errors"

// Sentinel errors from libp-registry's safe surface, beyond the kernel
// errno values (which surface as errno.Errno and match with errors.Is).

var (
	// ErrMalformedValue reports value bytes that do not match their type
	// tag — a REG_DWORD whose data is not four bytes, a REG_SZ that is not
	// valid UTF-8. It indicates data written by a non-libp producer (a
	// Windows hive import, say) under a libp-incompatible encoding. The
	// wrapping error names the offending type and detail.
	ErrMalformedValue = errors.New("value data does not match its type")

	// ErrReservedLayer reports an attempt to mutate the reserved base
	// layer in a way the kernel forbids (delete / disable / re-precedence),
	// rejected client-side before contacting the kernel.
	ErrReservedLayer = errors.New("the base layer is reserved")
)
