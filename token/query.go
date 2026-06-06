package token

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"unsafe"

	"github.com/peios/libp-go/wire"
	uapi "github.com/peios/pkm/uapi/go"
)

// QueryClass selects which token-information class Query returns.
type QueryClass uint32

// Token-information classes (KACS_TOKEN_CLASS_*).
const (
	ClassUser                       QueryClass = uapi.KACS_TOKEN_CLASS_USER
	ClassGroups                     QueryClass = uapi.KACS_TOKEN_CLASS_GROUPS
	ClassPrivileges                 QueryClass = uapi.KACS_TOKEN_CLASS_PRIVILEGES
	ClassType                       QueryClass = uapi.KACS_TOKEN_CLASS_TYPE
	ClassIntegrityLevel             QueryClass = uapi.KACS_TOKEN_CLASS_INTEGRITY_LEVEL
	ClassOwner                      QueryClass = uapi.KACS_TOKEN_CLASS_OWNER
	ClassPrimaryGroup               QueryClass = uapi.KACS_TOKEN_CLASS_PRIMARY_GROUP
	ClassSessionID                  QueryClass = uapi.KACS_TOKEN_CLASS_SESSION_ID
	ClassRestrictedSIDs             QueryClass = uapi.KACS_TOKEN_CLASS_RESTRICTED_SIDS
	ClassSource                     QueryClass = uapi.KACS_TOKEN_CLASS_SOURCE
	ClassStatistics                 QueryClass = uapi.KACS_TOKEN_CLASS_STATISTICS
	ClassOrigin                     QueryClass = uapi.KACS_TOKEN_CLASS_ORIGIN
	ClassElevationType              QueryClass = uapi.KACS_TOKEN_CLASS_ELEVATION_TYPE
	ClassDeviceGroups               QueryClass = uapi.KACS_TOKEN_CLASS_DEVICE_GROUPS
	ClassAppContainerSID            QueryClass = uapi.KACS_TOKEN_CLASS_APPCONTAINER_SID
	ClassCapabilities               QueryClass = uapi.KACS_TOKEN_CLASS_CAPABILITIES
	ClassMandatoryPolicy            QueryClass = uapi.KACS_TOKEN_CLASS_MANDATORY_POLICY
	ClassLogonType                  QueryClass = uapi.KACS_TOKEN_CLASS_LOGON_TYPE
	ClassLogonSID                   QueryClass = uapi.KACS_TOKEN_CLASS_LOGON_SID
	ClassDefaultDACL                QueryClass = uapi.KACS_TOKEN_CLASS_DEFAULT_DACL
	ClassImpersonationLevel         QueryClass = uapi.KACS_TOKEN_CLASS_IMPERSONATION_LEVEL
	ClassUserClaims                 QueryClass = uapi.KACS_TOKEN_CLASS_USER_CLAIMS
	ClassDeviceClaims               QueryClass = uapi.KACS_TOKEN_CLASS_DEVICE_CLAIMS
	ClassProjectedSupplementaryGIDs QueryClass = uapi.KACS_TOKEN_CLASS_PROJECTED_SUPPLEMENTARY_GIDS
)

// TokenType distinguishes a primary token from an impersonation token.
type TokenType uint32

const (
	TypePrimary       TokenType = uapi.KACS_TOKEN_TYPE_PRIMARY
	TypeImpersonation TokenType = uapi.KACS_TOKEN_TYPE_IMPERSONATION
)

// ImpersonationLevel is how far a server may act on an impersonation
// token's behalf.
type ImpersonationLevel uint32

const (
	LevelAnonymous      ImpersonationLevel = uapi.KACS_IMLEVEL_ANONYMOUS
	LevelIdentification ImpersonationLevel = uapi.KACS_IMLEVEL_IDENTIFICATION
	LevelImpersonation  ImpersonationLevel = uapi.KACS_IMLEVEL_IMPERSONATION
	LevelDelegation     ImpersonationLevel = uapi.KACS_IMLEVEL_DELEGATION
)

// ElevationType reports a token's elevation state.
type ElevationType uint32

const (
	ElevationDefault ElevationType = uapi.KACS_ELEVATION_DEFAULT
	ElevationFull    ElevationType = uapi.KACS_ELEVATION_FULL
	ElevationLimited ElevationType = uapi.KACS_ELEVATION_LIMITED
)

// Query returns the raw bytes of a token-information class. The typed
// accessors below cover the common classes; use Query directly for the
// rest. The kernel ABI for each class's byte layout is the KACS UAPI.
func (t *Token) Query(class QueryClass) ([]byte, error) {
	// Probe: a zero buf_len makes the kernel report the size it needs.
	probe := uapi.Kacs_query_args{Token_class: uint32(class)}
	if err := t.ioctl(uapi.KACS_IOC_QUERY, unsafe.Pointer(&probe)); err != nil {
		return nil, fmt.Errorf("libp/token: query class %d: %w", class, err)
	}
	n := probe.Buf_len
	if n == 0 {
		return nil, nil
	}

	// Fetch into a sized buffer.
	buf := make([]byte, n)
	args := uapi.Kacs_query_args{
		Token_class: uint32(class),
		Buf_len:     n,
		Buf_ptr:     uint64(uintptr(unsafe.Pointer(&buf[0]))),
	}
	err := t.ioctl(uapi.KACS_IOC_QUERY, unsafe.Pointer(&args))
	runtime.KeepAlive(buf)
	if err != nil {
		return nil, fmt.Errorf("libp/token: query class %d: %w", class, err)
	}
	got := args.Buf_len
	if got > n {
		return nil, fmt.Errorf("libp/token: query class %d: kernel wrote %d bytes into a %d-byte buffer", class, got, n)
	}
	return buf[:got], nil
}

// UserSID returns the SID of the user this token represents.
func (t *Token) UserSID() (wire.SID, error) { return t.sidClass(ClassUser) }

// PrimaryGroupSID returns the token's primary-group SID.
func (t *Token) PrimaryGroupSID() (wire.SID, error) { return t.sidClass(ClassPrimaryGroup) }

// OwnerSID returns the token's default owner SID.
func (t *Token) OwnerSID() (wire.SID, error) { return t.sidClass(ClassOwner) }

// IntegrityLevel returns the token's integrity-level SID.
func (t *Token) IntegrityLevel() (wire.SID, error) { return t.sidClass(ClassIntegrityLevel) }

func (t *Token) sidClass(class QueryClass) (wire.SID, error) {
	b, err := t.Query(class)
	if err != nil {
		return wire.SID{}, err
	}
	sid, err := wire.ParseSID(b)
	if err != nil {
		return wire.SID{}, fmt.Errorf("libp/token: query class %d: %w", class, err)
	}
	return sid, nil
}

// TokenType reports whether this is a primary or impersonation token.
func (t *Token) TokenType() (TokenType, error) {
	v, err := t.u32Class(ClassType)
	if err != nil {
		return 0, err
	}
	switch TokenType(v) {
	case TypePrimary, TypeImpersonation:
		return TokenType(v), nil
	default:
		return 0, fmt.Errorf("libp/token: unknown token type %d", v)
	}
}

// ImpersonationLevel returns the token's impersonation level — meaningful
// only for impersonation tokens.
func (t *Token) ImpersonationLevel() (ImpersonationLevel, error) {
	v, err := t.u32Class(ClassImpersonationLevel)
	if err != nil {
		return 0, err
	}
	switch ImpersonationLevel(v) {
	case LevelAnonymous, LevelIdentification, LevelImpersonation, LevelDelegation:
		return ImpersonationLevel(v), nil
	default:
		return 0, fmt.Errorf("libp/token: unknown impersonation level %d", v)
	}
}

// ElevationType returns the token's elevation state.
func (t *Token) ElevationType() (ElevationType, error) {
	v, err := t.u32Class(ClassElevationType)
	if err != nil {
		return 0, err
	}
	switch ElevationType(v) {
	case ElevationDefault, ElevationFull, ElevationLimited:
		return ElevationType(v), nil
	default:
		return 0, fmt.Errorf("libp/token: unknown elevation type %d", v)
	}
}

// SessionID returns the id of the session this token belongs to. The
// per-token session id is a uint32 in the KACS ABI, distinct from the
// uint64 SessionID minted by CreateSession.
func (t *Token) SessionID() (uint32, error) {
	return t.u32Class(ClassSessionID)
}

func (t *Token) u32Class(class QueryClass) (uint32, error) {
	b, err := t.Query(class)
	if err != nil {
		return 0, err
	}
	if len(b) < 4 {
		return 0, fmt.Errorf("libp/token: query class %d: want 4 bytes, got %d", class, len(b))
	}
	return binary.LittleEndian.Uint32(b), nil
}
