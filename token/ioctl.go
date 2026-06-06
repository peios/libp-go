package token

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/peios/libp-go/errno"
	uapi "github.com/peios/pkm/uapi/go"
)

// ioctl issues one ioctl against the token fd. arg points at the ioctl
// argument struct, or is nil for the argument-less ioctls.
func (t *Token) ioctl(request uintptr, arg unsafe.Pointer) error {
	_, err := retry(func() (uintptr, syscall.Errno) {
		_, _, e := syscall.Syscall(syscall.SYS_IOCTL,
			uintptr(t.fd), request, uintptr(arg))
		return 0, e
	})
	return err
}

// Duplicate copies this token, optionally changing its access mask,
// type (primary vs impersonation), or impersonation level.
func (t *Token) Duplicate(access Access, typ TokenType, level ImpersonationLevel) (*Token, error) {
	args := uapi.Kacs_duplicate_args{
		Access_mask:         uint32(access),
		Token_type:          uint32(typ),
		Impersonation_level: uint32(level),
		Result_fd:           -1,
	}
	if err := t.ioctl(uapi.KACS_IOC_DUPLICATE, unsafe.Pointer(&args)); err != nil {
		return nil, fmt.Errorf("libp/token: duplicate: %w", err)
	}
	return &Token{fd: int(args.Result_fd)}, nil
}

// RestrictFlags modifies a Restrict call.
type RestrictFlags uint32

// RestrictWriteRestricted marks the resulting token write-restricted.
const RestrictWriteRestricted RestrictFlags = uapi.KACS_TOKEN_RESTRICT_WRITE_RESTRICTED

// RestrictSpec describes a token restriction: privileges to drop, and
// SID-table entries to mark deny-only or restricted.
type RestrictSpec struct {
	// PrivilegesToDelete is a bit-mask of KACS_SE_*_PRIVILEGE values to
	// remove from the restricted token.
	PrivilegesToDelete uint64
	// DenyIndexCount and RestrictSIDCount partition Payload into its
	// deny-index and restricted-SID sections, in that order.
	DenyIndexCount   uint32
	RestrictSIDCount uint32
	// Payload is the concatenated deny-index / restricted-SID data.
	Payload []byte
	// Flags is a bit-mask of Restrict* values.
	Flags RestrictFlags
}

// Restrict derives a new, restricted token from this one.
func (t *Token) Restrict(spec RestrictSpec) (*Token, error) {
	var ptr unsafe.Pointer
	if len(spec.Payload) > 0 {
		ptr = unsafe.Pointer(&spec.Payload[0])
	}
	args := uapi.Kacs_restrict_args{
		Privs_to_delete:   spec.PrivilegesToDelete,
		Num_deny_indices:  spec.DenyIndexCount,
		Num_restrict_sids: spec.RestrictSIDCount,
		Data_len:          uint32(len(spec.Payload)),
		Flags:             uint32(spec.Flags),
		Data_ptr:          uint64(uintptr(ptr)),
		Result_fd:         -1,
	}
	err := t.ioctl(uapi.KACS_IOC_RESTRICT, unsafe.Pointer(&args))
	runtime.KeepAlive(spec.Payload)
	if err != nil {
		return nil, fmt.Errorf("libp/token: restrict: %w", err)
	}
	return &Token{fd: int(args.Result_fd)}, nil
}

// Install installs this token as the calling task's primary token.
func (t *Token) Install() error {
	if err := t.ioctl(uapi.KACS_IOC_INSTALL, nil); err != nil {
		return fmt.Errorf("libp/token: install: %w", err)
	}
	return nil
}

// LinkTokens links this (elevated) token to a filtered counterpart,
// forming an elevation pair within the given session.
func (t *Token) LinkTokens(filtered *Token, session SessionID) error {
	args := uapi.Kacs_link_tokens_args{
		Elevated_fd: int32(t.fd),
		Filtered_fd: int32(filtered.fd),
		Session_id:  uint64(session),
	}
	if err := t.ioctl(uapi.KACS_IOC_LINK_TOKENS, unsafe.Pointer(&args)); err != nil {
		return fmt.Errorf("libp/token: link tokens: %w", err)
	}
	return nil
}

// LinkedToken returns this token's linked counterpart. It fails with
// ENOENT if the token has no linked counterpart.
func (t *Token) LinkedToken() (*Token, error) {
	args := uapi.Kacs_get_linked_token_args{Result_fd: -1}
	if err := t.ioctl(uapi.KACS_IOC_GET_LINKED_TOKEN, unsafe.Pointer(&args)); err != nil {
		return nil, fmt.Errorf("libp/token: linked token: %w", err)
	}
	return &Token{fd: int(args.Result_fd)}, nil
}

// PrivEntry is one privilege adjustment: a privilege LUID and the
// attributes (KACS_PRIVILEGE_ATTR_*) to apply to it.
type PrivEntry struct {
	LUID       uint32
	Attributes uint32
}

// AdjustPrivileges applies privilege adjustments and returns the mask of
// privileges that were previously enabled. The kernel rejects an empty
// slice with EINVAL, so the call is short-circuited for one.
func (t *Token) AdjustPrivileges(entries []PrivEntry) (previous uint64, err error) {
	if len(entries) == 0 {
		return 0, fmt.Errorf("libp/token: adjust privileges: %w", errno.EINVAL)
	}
	raw := make([]uapi.Kacs_priv_entry, len(entries))
	for i, e := range entries {
		raw[i] = uapi.Kacs_priv_entry{Luid: e.LUID, Attributes: e.Attributes}
	}
	args := uapi.Kacs_adjust_privs_args{
		Count:    uint32(len(raw)),
		Data_ptr: uint64(uintptr(unsafe.Pointer(&raw[0]))),
	}
	e := t.ioctl(uapi.KACS_IOC_ADJUST_PRIVS, unsafe.Pointer(&args))
	runtime.KeepAlive(raw)
	if e != nil {
		return 0, fmt.Errorf("libp/token: adjust privileges: %w", e)
	}
	return args.Previous_enabled, nil
}

// GroupEntry enables or disables a token group by its index in the
// token's group list.
type GroupEntry struct {
	Index   uint32
	Enabled bool
}

// AdjustGroups applies group enable/disable changes and returns the
// previous group-state as a 1024-bit mask in sixteen 64-bit words: bit
// i%64 of word i/64 is group i. The kernel rejects an empty slice with
// EINVAL, so the call is short-circuited for one.
func (t *Token) AdjustGroups(entries []GroupEntry) (previous [16]uint64, err error) {
	if len(entries) == 0 {
		return previous, fmt.Errorf("libp/token: adjust groups: %w", errno.EINVAL)
	}
	raw := make([]uapi.Kacs_group_entry, len(entries))
	for i, e := range entries {
		raw[i].Index = e.Index
		if e.Enabled {
			raw[i].Enable = 1
		}
	}
	args := uapi.Kacs_adjust_groups_args{
		Count:    uint32(len(raw)),
		Data_ptr: uint64(uintptr(unsafe.Pointer(&raw[0]))),
	}
	e := t.ioctl(uapi.KACS_IOC_ADJUST_GROUPS, unsafe.Pointer(&args))
	runtime.KeepAlive(raw)
	if e != nil {
		return previous, fmt.Errorf("libp/token: adjust groups: %w", e)
	}
	return args.Previous_state, nil
}

// AdjustDefault sets the token's default DACL and the indices of its
// owner and primary group within the group list. Pass dacl == nil to
// leave the default DACL unchanged.
func (t *Token) AdjustDefault(dacl []byte, ownerIndex, groupIndex uint16) error {
	var ptr unsafe.Pointer
	if len(dacl) > 0 {
		ptr = unsafe.Pointer(&dacl[0])
	}
	args := uapi.Kacs_adjust_default_args{
		Dacl_ptr:    uint64(uintptr(ptr)),
		Dacl_len:    uint32(len(dacl)),
		Owner_index: ownerIndex,
		Group_index: groupIndex,
	}
	err := t.ioctl(uapi.KACS_IOC_ADJUST_DEFAULT, unsafe.Pointer(&args))
	runtime.KeepAlive(dacl)
	if err != nil {
		return fmt.Errorf("libp/token: adjust default: %w", err)
	}
	return nil
}

// SetSessionID changes the session id recorded on this token.
func (t *Token) SetSessionID(id uint32) error {
	v := id
	if err := t.ioctl(uapi.KACS_IOC_ADJUST_SESSIONID, unsafe.Pointer(&v)); err != nil {
		return fmt.Errorf("libp/token: set session id: %w", err)
	}
	return nil
}
