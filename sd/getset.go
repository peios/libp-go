package sd

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/peios/libp-go/internal/sys"
	uapi "github.com/peios/pkm/uapi/go"
)

// ErrNotSelfRelative reports a security descriptor that is not in the
// self-relative form the KACS ABI requires.
var ErrNotSelfRelative = errors.New("libp/sd: security descriptor is not self-relative")

// at* are the dirfd / resolution flags get_sd and set_sd accept.
const (
	atFDCWD           = -0x64  // resolve a path against the working directory
	atEmptyPath       = 0x1000 // operate on dirfd itself, with an empty path
	atSymlinkNoFollow = 0x100  // act on a symlink, not its target
)

// Info is a SECURITY_INFORMATION bitset — which components of a security
// descriptor a GetSD / SetSD call reads or writes.
type Info uint32

const (
	InfoOwner Info = uapi.KACS_SECINFO_OWNER
	InfoGroup Info = uapi.KACS_SECINFO_GROUP
	InfoDACL  Info = uapi.KACS_SECINFO_DACL
	InfoSACL  Info = uapi.KACS_SECINFO_SACL
	InfoLabel Info = uapi.KACS_SECINFO_LABEL
)

// InfoAll selects owner, group, DACL, and SACL. It deliberately omits
// InfoLabel: the kernel rejects a request that sets both SACL and Label
// (the mandatory label is a view of the SACL slot, not a separate
// component).
const InfoAll = InfoOwner | InfoGroup | InfoDACL | InfoSACL

// Target is what a GetSD / SetSD call operates on — a path or an open
// file descriptor. Build one with Path, PathAt, or FD.
type Target struct {
	dirfd int
	path  string
	flags uint32
}

// Path targets a filesystem path, resolved against the working directory.
func Path(path string) Target {
	return Target{dirfd: atFDCWD, path: path}
}

// PathAt targets a path resolved against the directory referenced by
// dirfd.
func PathAt(dirfd int, path string) Target {
	return Target{dirfd: dirfd, path: path}
}

// FD targets an already-open file descriptor — a file fd or a KACS token
// fd.
func FD(fd int) Target {
	return Target{dirfd: fd, flags: atEmptyPath}
}

// NoFollowSymlinks returns a copy of t that acts on a symlink itself
// rather than its target. It has no effect on an FD target.
func (t Target) NoFollowSymlinks() Target {
	t.flags |= atSymlinkNoFollow
	return t
}

// GetSD reads the security descriptor of t, returning the raw
// self-relative bytes — decode them with ParseDescriptor. Only the
// components selected by info are returned.
func GetSD(t Target, info Info) ([]byte, error) {
	cpath, err := syscall.BytePtrFromString(t.path)
	if err != nil {
		return nil, fmt.Errorf("libp/sd: get sd %q: invalid path: %w", t.path, err)
	}
	call := func(buf []byte) (uintptr, error) {
		var bufPtr unsafe.Pointer
		if len(buf) > 0 {
			bufPtr = unsafe.Pointer(&buf[0])
		}
		r, e := retry(func() (uintptr, syscall.Errno) {
			r1, _, errno := syscall.Syscall6(uapi.SYS_KACS_GET_SD,
				uintptr(t.dirfd), uintptr(unsafe.Pointer(cpath)),
				uintptr(info), uintptr(bufPtr), uintptr(len(buf)),
				uintptr(t.flags))
			return r1, errno
		})
		runtime.KeepAlive(cpath)
		runtime.KeepAlive(buf)
		return r, e
	}

	// Probe with a zero-length buffer: the kernel reports the size.
	needed, err := call(nil)
	if err != nil {
		return nil, fmt.Errorf("libp/sd: get sd %q: %w", t.path, err)
	}
	if needed == 0 {
		return nil, nil
	}
	buf := make([]byte, needed)
	got, err := call(buf)
	if err != nil {
		return nil, fmt.Errorf("libp/sd: get sd %q: %w", t.path, err)
	}
	if got > needed {
		return nil, fmt.Errorf("libp/sd: get sd %q: descriptor grew between probe and fetch (%d > %d)", t.path, got, needed)
	}
	return buf[:got], nil
}

// SetSD writes sdBytes — a self-relative security descriptor — to t.
// Only the components selected by info are applied.
func SetSD(t Target, info Info, sdBytes []byte) error {
	cpath, err := syscall.BytePtrFromString(t.path)
	if err != nil {
		return fmt.Errorf("libp/sd: set sd %q: invalid path: %w", t.path, err)
	}
	var sdPtr unsafe.Pointer
	if len(sdBytes) > 0 {
		sdPtr = unsafe.Pointer(&sdBytes[0])
	}
	_, err = retry(func() (uintptr, syscall.Errno) {
		r1, _, e := syscall.Syscall6(uapi.SYS_KACS_SET_SD,
			uintptr(t.dirfd), uintptr(unsafe.Pointer(cpath)),
			uintptr(info), uintptr(sdPtr), uintptr(len(sdBytes)),
			uintptr(t.flags))
		return r1, e
	})
	runtime.KeepAlive(cpath)
	runtime.KeepAlive(sdBytes)
	if err != nil {
		return fmt.Errorf("libp/sd: set sd %q: %w", t.path, err)
	}
	return nil
}

// StripInheritedACEs returns a copy of sdBytes with the inherited ACEs
// (those with the FlagInherited flag) removed from the ACLs selected by
// info. Owner, group, and the control word pass through; an ACL not
// selected by info is left intact. If info selects neither DACL nor
// SACL, sdBytes is returned unchanged.
//
// The result is re-marshalled through the codec, so an ACL's revision
// byte is normalised to the minimum valid value rather than preserved
// verbatim — functionally equivalent, but not byte-identical to a
// non-minimal source revision.
func StripInheritedACEs(sdBytes []byte, info Info) ([]byte, error) {
	if info&(InfoDACL|InfoSACL) == 0 {
		return append([]byte(nil), sdBytes...), nil
	}
	d, err := ParseDescriptor(sdBytes)
	if err != nil {
		return nil, fmt.Errorf("libp/sd: strip inherited: %w", err)
	}
	if d.Control&ControlSelfRelative == 0 {
		return nil, ErrNotSelfRelative
	}
	if info&InfoDACL != 0 && d.DACL != nil {
		d.DACL = filterInherited(d.DACL)
	}
	if info&InfoSACL != 0 && d.SACL != nil {
		d.SACL = filterInherited(d.SACL)
	}
	out, err := d.Marshal()
	if err != nil {
		return nil, fmt.Errorf("libp/sd: strip inherited: %w", err)
	}
	return out, nil
}

// filterInherited returns a copy of l keeping only its non-inherited ACEs.
func filterInherited(l *ACL) *ACL {
	kept := make([]ACE, 0, len(l.Entries))
	for _, a := range l.Entries {
		if a.Flags&FlagInherited == 0 {
			kept = append(kept, a)
		}
	}
	return &ACL{Entries: kept}
}

// retry is this package's handle on the shared EINTR-retrying syscall
// helper, libp-go/internal/sys.
var retry = sys.Retry
