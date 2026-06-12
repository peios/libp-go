package registry

import (
	"fmt"
	"runtime"
	"syscall"

	"github.com/peios/libp-go/internal/sys"
	uapi "github.com/peios/pkm/uapi/go"
)

// Disposition reports whether a Create call created the key or opened an
// existing one.
type Disposition uint32

const (
	// CreatedNew: the key did not exist and was created.
	CreatedNew Disposition = uapi.REG_CREATED_NEW
	// OpenedExisting: the key already existed and was opened (the target
	// layer was ignored).
	OpenedExisting Disposition = uapi.REG_OPENED_EXISTING
)

// String names the disposition.
func (d Disposition) String() string {
	switch d {
	case CreatedNew:
		return "CreatedNew"
	case OpenedExisting:
		return "OpenedExisting"
	default:
		return fmt.Sprintf("Disposition(%d)", uint32(d))
	}
}

// CreateOptions is a fluent builder for a reg_create_key call. Create
// opens the key if it exists (the target layer is ignored) or creates it
// with an inherited SD if it doesn't, reporting which happened via
// Disposition. It mirrors libp-files' OpenOptions.
//
// Access defaults to MaximumAllowed — the inherited SD on a freshly
// created key may not grant everything, so "give me what it grants" is the
// safe default; override with Access. The target layer defaults to base.
type CreateOptions struct {
	parentFD int
	path     string
	access   uint32
	layer    string
	flags    uint32
	txnFD    int
}

// Create starts a create-or-open for an absolute path. Configure with the
// builder methods, then Call.
func Create(path string) *CreateOptions {
	return createAt(parentNone, path)
}

func createAt(parentFD int, path string) *CreateOptions {
	return &CreateOptions{
		parentFD: parentFD,
		path:     path,
		access:   uint32(MaximumAllowed),
		txnFD:    noTxn,
	}
}

// Access sets the desired-access mask requested on the resulting key fd.
func (c *CreateOptions) Access(access Access) *CreateOptions {
	c.access = access.bits()
	return c
}

// Layer targets a named layer for the created key's path entry (default
// base). Ignored if the key already exists.
func (c *CreateOptions) Layer(name string) *CreateOptions {
	c.layer = name
	return c
}

// Volatile creates a volatile key (does not survive reboot).
func (c *CreateOptions) Volatile() *CreateOptions {
	c.flags |= uapi.REG_OPTION_VOLATILE
	return c
}

// CreateLink creates a symlink key (requires CreateLink access +
// SeTcbPrivilege/Administrator).
func (c *CreateOptions) CreateLink() *CreateOptions {
	c.flags |= uapi.REG_OPTION_CREATE_LINK
	return c
}

// withTxn enlists the create in a transaction.
func (c *CreateOptions) withTxn(txnFD int) *CreateOptions {
	c.txnFD = txnFD
	return c
}

// Call performs the create-or-open, returning the key and which happened.
func (c *CreateOptions) Call() (*Key, Disposition, error) {
	cpath, err := syscall.BytePtrFromString(c.path)
	if err != nil {
		return nil, 0, fmt.Errorf("libp/registry: create %q: invalid path: %w", c.path, err)
	}
	var clayer *byte
	if c.layer != "" {
		clayer, err = syscall.BytePtrFromString(c.layer)
		if err != nil {
			return nil, 0, fmt.Errorf("libp/registry: create %q: invalid layer %q: %w", c.path, c.layer, err)
		}
	}
	var disposition uint32
	args := uapi.Reg_create_key_args{
		Parent_fd:       int32(c.parentFD),
		Path_ptr:        uint64(uintptr(ptr(cpath))),
		Desired_access:  c.access,
		Flags:           c.flags,
		Txn_fd:          int32(c.txnFD),
		Disposition_ptr: uint64(uintptr(ptr(&disposition))),
	}
	if clayer != nil {
		args.Layer_ptr = uint64(uintptr(ptr(clayer)))
	}
	r, err := sys.Retry(func() (uintptr, syscall.Errno) {
		return createKey(&args)
	})
	runtime.KeepAlive(cpath)
	runtime.KeepAlive(clayer)
	if err != nil {
		return nil, 0, fmt.Errorf("libp/registry: create %q: %w", c.path, err)
	}
	return &Key{fd: int(r)}, Disposition(disposition), nil
}
