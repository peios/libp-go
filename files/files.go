// Package files is the libp interface to KACS files — the native,
// NtCreateFile-shaped open, and per-mount security policy (mount.go).
//
// It is a libp-tier package: an idiomatic Go surface over the generated
// uapi binding. See libp-design.md and libp-map.md.
package files

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/peios/libp-go/internal/sys"
	uapi "github.com/peios/pkm/uapi/go"
)

// Access is a KACS file access mask — the rights an open requests.
// Values combine with bitwise OR.
type Access uint32

// File and directory object-specific rights — the low 16 bits of a file
// access mask, from pkm <pkm/file.h>. The directory aliases name the
// same bit as the file right they act as for a directory object.
const (
	ReadData        Access = uapi.KACS_FILE_READ_DATA
	WriteData       Access = uapi.KACS_FILE_WRITE_DATA
	AppendData      Access = uapi.KACS_FILE_APPEND_DATA
	ReadEA          Access = uapi.KACS_FILE_READ_EA
	WriteEA         Access = uapi.KACS_FILE_WRITE_EA
	Execute         Access = uapi.KACS_FILE_EXECUTE
	DeleteChild     Access = uapi.KACS_FILE_DELETE_CHILD
	ReadAttributes  Access = uapi.KACS_FILE_READ_ATTRIBUTES
	WriteAttributes Access = uapi.KACS_FILE_WRITE_ATTRIBUTES

	ListDirectory   Access = uapi.KACS_FILE_LIST_DIRECTORY
	Traverse        Access = uapi.KACS_FILE_TRAVERSE
	AddFile         Access = uapi.KACS_FILE_ADD_FILE
	AddSubdirectory Access = uapi.KACS_FILE_ADD_SUBDIRECTORY
)

// Standard and generic rights, from pkm <pkm/sd.h>. These bits are not
// file-specific; they are duplicated here pending the sd slice, which
// will own the shared access-mask vocabulary.
const (
	Delete      Access = uapi.KACS_ACCESS_DELETE
	ReadControl Access = uapi.KACS_ACCESS_READ_CONTROL
	WriteDAC    Access = uapi.KACS_ACCESS_WRITE_DAC
	WriteOwner  Access = uapi.KACS_ACCESS_WRITE_OWNER
	Synchronize Access = uapi.KACS_ACCESS_SYNCHRONIZE

	GenericRead    Access = uapi.KACS_ACCESS_GENERIC_READ
	GenericWrite   Access = uapi.KACS_ACCESS_GENERIC_WRITE
	GenericExecute Access = uapi.KACS_ACCESS_GENERIC_EXECUTE
	GenericAll     Access = uapi.KACS_ACCESS_GENERIC_ALL
)

// Disposition tells Open how to behave when the target does or does not
// already exist. The zero value, DispOpen, opens an existing file and
// fails if it is absent — so a zero OpenOptions never creates or
// truncates anything.
type Disposition uint32

const (
	DispOpen        Disposition = iota // open existing; ENOENT if absent
	DispCreate                         // create new; EEXIST if present
	DispOpenIf                         // open if present, else create
	DispSupersede                      // replace wholesale; create if absent
	DispOverwrite                      // open + truncate; fail if absent
	DispOverwriteIf                    // open + truncate, else create
)

// kacs maps a Disposition to its KACS create-disposition value. ok is
// false for a Disposition outside the defined set.
func (d Disposition) kacs() (v uint32, ok bool) {
	switch d {
	case DispOpen:
		return uapi.KACS_DISPOSITION_OPEN, true
	case DispCreate:
		return uapi.KACS_DISPOSITION_CREATE, true
	case DispOpenIf:
		return uapi.KACS_DISPOSITION_OPEN_IF, true
	case DispSupersede:
		return uapi.KACS_DISPOSITION_SUPERSEDE, true
	case DispOverwrite:
		return uapi.KACS_DISPOSITION_OVERWRITE, true
	case DispOverwriteIf:
		return uapi.KACS_DISPOSITION_OVERWRITE_IF, true
	default:
		return 0, false
	}
}

// OpenStatus reports what Open actually did to the target.
type OpenStatus uint32

const (
	StatusOpened      OpenStatus = uapi.KACS_STATUS_OPENED
	StatusCreated     OpenStatus = uapi.KACS_STATUS_CREATED
	StatusOverwritten OpenStatus = uapi.KACS_STATUS_OVERWRITTEN
	StatusSuperseded  OpenStatus = uapi.KACS_STATUS_SUPERSEDED
)

// OpenOptions configures an Open call. The zero value opens an existing
// file with no access rights — set at least Access and Disposition.
type OpenOptions struct {
	// Access is the desired-access mask.
	Access Access
	// Disposition selects create/open behaviour. The zero value opens
	// an existing file and fails if it is absent.
	Disposition Disposition
	// Directory requires the target to be — or to be created as — a
	// directory.
	Directory bool
	// DeleteOnClose deletes the file once its last handle closes.
	DeleteOnClose bool
	// BackupIntent and RestoreIntent open with backup / restore intent.
	BackupIntent  bool
	RestoreIntent bool
	// SecurityDescriptor is a self-relative security descriptor applied
	// to the file if this open creates it; ignored for opens of an
	// existing file.
	SecurityDescriptor []byte
}

// FileHandle is an open handle to a KACS file. Call Close when done.
type FileHandle struct {
	fd int
}

// FD returns the underlying kernel file descriptor, valid until Close.
func (f *FileHandle) FD() int { return f.fd }

// Close releases the file handle. It is safe to call more than once.
func (f *FileHandle) Close() error {
	if f.fd < 0 {
		return nil
	}
	err := syscall.Close(f.fd)
	f.fd = -1
	if err != nil {
		return fmt.Errorf("libp/files: close: %w", err)
	}
	return nil
}

// AT_FDCWD, passed as the dirfd to OpenAt, resolves the path against the
// process working directory (the Linux AT_FDCWD value).
const AT_FDCWD = -0x64

// Open opens path relative to the current working directory.
func Open(path string, opts OpenOptions) (*FileHandle, OpenStatus, error) {
	return OpenAt(AT_FDCWD, path, opts)
}

// OpenAt opens path relative to the directory referenced by dirfd. Pass
// AT_FDCWD for dirfd to resolve against the working directory.
func OpenAt(dirfd int, path string, opts OpenOptions) (*FileHandle, OpenStatus, error) {
	disp, ok := opts.Disposition.kacs()
	if !ok {
		return nil, 0, fmt.Errorf("libp/files: open %q: invalid disposition %d", path, opts.Disposition)
	}
	cpath, err := syscall.BytePtrFromString(path)
	if err != nil {
		return nil, 0, fmt.Errorf("libp/files: open %q: invalid path: %w", path, err)
	}

	var createOpts uint32
	if opts.Directory {
		createOpts |= uapi.KACS_CREATE_OPT_DIRECTORY
	}
	if opts.DeleteOnClose {
		createOpts |= uapi.KACS_CREATE_OPT_DELETE_ON_CLOSE
	}
	var flags uint32
	if opts.BackupIntent {
		flags |= uapi.KACS_BACKUP_INTENT
	}
	if opts.RestoreIntent {
		flags |= uapi.KACS_RESTORE_INTENT
	}
	var sdPtr unsafe.Pointer
	if len(opts.SecurityDescriptor) > 0 {
		sdPtr = unsafe.Pointer(&opts.SecurityDescriptor[0])
	}
	how := uapi.Kacs_open_how{
		Desired_access:     uint32(opts.Access),
		Create_disposition: disp,
		Create_options:     createOpts,
		Flags:              flags,
		Sd_ptr:             uint64(uintptr(sdPtr)),
		Sd_len:             uint32(len(opts.SecurityDescriptor)),
	}

	var status uint32
	r, err := retry(func() (uintptr, syscall.Errno) {
		r1, _, e := syscall.Syscall6(uapi.SYS_KACS_OPEN,
			uintptr(dirfd),
			uintptr(unsafe.Pointer(cpath)),
			uintptr(unsafe.Pointer(&how)),
			unsafe.Sizeof(how),
			uintptr(unsafe.Pointer(&status)),
			0)
		return r1, e
	})
	runtime.KeepAlive(cpath)
	runtime.KeepAlive(opts.SecurityDescriptor)
	if err != nil {
		return nil, 0, fmt.Errorf("libp/files: open %q: %w", path, err)
	}

	fh := &FileHandle{fd: int(r)}
	switch st := OpenStatus(status); st {
	case StatusOpened, StatusCreated, StatusOverwritten, StatusSuperseded:
		return fh, st, nil
	default:
		fh.Close()
		return nil, 0, fmt.Errorf("libp/files: open %q: kernel reported unknown status %d", path, status)
	}
}

// retry runs a syscall closure, retrying transparently on EINTR, and
// maps a nonzero kernel errno to an errno.Errno. The closure performs
// the syscall itself, so any unsafe.Pointer conversion stays inside the
// syscall call, as the runtime requires.
var retry = sys.Retry
