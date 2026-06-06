package sd

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/peios/libp-go/errno"
	"github.com/peios/libp-go/token"
	"github.com/peios/libp-go/wire"
	uapi "github.com/peios/pkm/uapi/go"
)

// GenericMapping expands the four generic access bits (read / write /
// execute / all) to object-class-specific rights during an access check.
type GenericMapping struct {
	Read    uint32
	Write   uint32
	Execute uint32
	All     uint32
}

// CheckRequest describes an access check. SD and DesiredAccess are
// required; every other field is optional, a zero value meaning absent.
//
// Token is the token the check runs against. A nil Token means the
// caller's own effective token — the kernel resolves it directly, no
// token handle needed. (It is a *token.Token, not a raw fd, precisely
// so the nil/zero value is "self": a zero fd is a valid descriptor, so a
// raw-fd field would have an unsafe default.)
type CheckRequest struct {
	Token           *token.Token
	SD              []byte // self-relative security descriptor
	DesiredAccess   uint32
	Mapping         GenericMapping
	SelfSID         wire.SID // PRINCIPAL_SELF substitution; zero = none
	PrivilegeIntent uint32
	ObjectTree      []ObjectNode
	LocalClaims     []Claim
	PIPType         uint32
	PIPTrust        uint32
	AuditContext    []byte
}

// Decision is the outcome of a scalar access check.
type Decision struct {
	Granted     bool
	GrantedMask uint32
}

// NodeDecision is the per-node outcome of an object-tree access check.
type NodeDecision struct {
	GrantedMask uint32
	Status      int32
}

// bufPtr is the address of b's first byte as a u64, or 0 if b is empty.
func bufPtr(b []byte) uint64 {
	if len(b) == 0 {
		return 0
	}
	return uint64(uintptr(unsafe.Pointer(&b[0])))
}

// tokenFD is the kernel token_fd for an access check: the handle's fd,
// or -1 — the "caller's own effective token" sentinel — when t is nil.
func tokenFD(t *token.Token) int32 {
	if t == nil {
		return -1
	}
	return int32(t.FD())
}

// assemble builds the access-check args struct and the side buffers its
// pointer fields reference. The buffers must outlive the syscall.
func (req CheckRequest) assemble() (uapi.Kacs_access_check_args, [][]byte, error) {
	if len(req.SD) == 0 {
		return uapi.Kacs_access_check_args{}, nil,
			errors.New("libp/sd: access check requires a security descriptor")
	}
	claims, err := EncodeClaimsArray(req.LocalClaims)
	if err != nil {
		return uapi.Kacs_access_check_args{}, nil, err
	}
	objTree := EncodeObjectTree(req.ObjectTree)
	var selfSID []byte
	if req.SelfSID.IsValid() {
		selfSID = req.SelfSID.Bytes()
	}
	args := uapi.Kacs_access_check_args{
		Caller_size:       uapi.KACS_ACCESS_CHECK_ARGS_SIZE,
		Token_fd:          tokenFD(req.Token),
		Sd_ptr:            bufPtr(req.SD),
		Sd_len:            uint32(len(req.SD)),
		Desired_access:    req.DesiredAccess,
		Mapping_read:      req.Mapping.Read,
		Mapping_write:     req.Mapping.Write,
		Mapping_execute:   req.Mapping.Execute,
		Mapping_all:       req.Mapping.All,
		Self_sid_ptr:      bufPtr(selfSID),
		Self_sid_len:      uint32(len(selfSID)),
		Privilege_intent:  req.PrivilegeIntent,
		Object_tree_ptr:   bufPtr(objTree),
		Object_tree_count: uint32(len(req.ObjectTree)),
		Local_claims_ptr:  bufPtr(claims),
		Local_claims_len:  uint32(len(claims)),
		Pip_type:          req.PIPType,
		Pip_trust:         req.PIPTrust,
		Audit_context_ptr: bufPtr(req.AuditContext),
		Audit_context_len: uint32(len(req.AuditContext)),
	}
	return args, [][]byte{req.SD, selfSID, objTree, claims, req.AuditContext}, nil
}

// Check runs a scalar access check. A denial is reported as
// Decision{Granted: false} — not an error; only a genuine syscall
// failure returns a non-nil error.
func Check(req CheckRequest) (Decision, error) {
	args, keep, err := req.assemble()
	if err != nil {
		return Decision{}, err
	}
	var granted uint32
	args.Granted_out_ptr = uint64(uintptr(unsafe.Pointer(&granted)))

	_, callErr := retry(func() (uintptr, syscall.Errno) {
		_, _, e := syscall.Syscall(uapi.SYS_KACS_ACCESS_CHECK,
			uintptr(unsafe.Pointer(&args)), 0, 0)
		return 0, e
	})
	runtime.KeepAlive(keep)
	if callErr != nil {
		if errors.Is(callErr, errno.EACCES) {
			return Decision{Granted: false, GrantedMask: granted}, nil
		}
		return Decision{}, fmt.Errorf("libp/sd: access check: %w", callErr)
	}
	return Decision{Granted: true, GrantedMask: granted}, nil
}

// CheckList runs an object-tree access check, returning one NodeDecision
// per ObjectTree node in tree order. It requires at least one node.
func CheckList(req CheckRequest) ([]NodeDecision, error) {
	if len(req.ObjectTree) == 0 {
		return nil, errors.New("libp/sd: access check list requires at least one object-tree node")
	}
	args, keep, err := req.assemble()
	if err != nil {
		return nil, err
	}
	var granted uint32
	args.Granted_out_ptr = uint64(uintptr(unsafe.Pointer(&granted)))
	results := make([]uapi.Kacs_node_result, len(req.ObjectTree))

	_, callErr := retry(func() (uintptr, syscall.Errno) {
		_, _, e := syscall.Syscall(uapi.SYS_KACS_ACCESS_CHECK_LIST,
			uintptr(unsafe.Pointer(&args)),
			uintptr(unsafe.Pointer(&results[0])),
			uintptr(len(results)))
		return 0, e
	})
	runtime.KeepAlive(keep)
	runtime.KeepAlive(results)
	if callErr != nil {
		return nil, fmt.Errorf("libp/sd: access check list: %w", callErr)
	}
	out := make([]NodeDecision, len(results))
	for i, r := range results {
		out[i] = NodeDecision{GrantedMask: r.Granted, Status: r.Status}
	}
	return out, nil
}
