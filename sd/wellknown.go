// Package sd is the libp interface to KACS security descriptors — the
// SID / SD / ACL / ACE wire codec, access checks, and the get/set
// security-descriptor syscalls.
//
// It is a libp-tier package: an idiomatic Go surface over the generated
// uapi binding and the wire primitives. See libp-design.md and
// libp-map.md.
package sd

import "github.com/peios/libp-go/wire"

// WellKnown identifies a well-known SID — a system principal or an
// integrity level whose SID is fixed by the platform.
type WellKnown int

const (
	Null WellKnown = iota
	Everyone
	Anonymous
	AuthenticatedUsers
	LocalSystem
	LocalService
	NetworkService
	BuiltinAdministrators
	BuiltinUsers
	UntrustedIL
	LowIL
	MediumIL
	MediumPlusIL
	HighIL
	SystemIL
	ProtectedProcessIL
	CreatorOwner
	CreatorGroup
)

// allWellKnown lists every WellKnown, for LookupWellKnown.
var allWellKnown = []WellKnown{
	Null, Everyone, Anonymous, AuthenticatedUsers, LocalSystem,
	LocalService, NetworkService, BuiltinAdministrators, BuiltinUsers,
	UntrustedIL, LowIL, MediumIL, MediumPlusIL, HighIL, SystemIL,
	ProtectedProcessIL, CreatorOwner, CreatorGroup,
}

// parts returns the identifier authority and sub-authorities of a
// well-known SID; the revision is always 1.
func (w WellKnown) parts() (authority uint64, subs []uint32) {
	switch w {
	case Null:
		return 0, []uint32{0}
	case Everyone:
		return 1, []uint32{0}
	case Anonymous:
		return 5, []uint32{7}
	case AuthenticatedUsers:
		return 5, []uint32{11}
	case LocalSystem:
		return 5, []uint32{18}
	case LocalService:
		return 5, []uint32{19}
	case NetworkService:
		return 5, []uint32{20}
	case BuiltinAdministrators:
		return 5, []uint32{32, 544}
	case BuiltinUsers:
		return 5, []uint32{32, 545}
	case UntrustedIL:
		return 16, []uint32{0}
	case LowIL:
		return 16, []uint32{4096}
	case MediumIL:
		return 16, []uint32{8192}
	case MediumPlusIL:
		return 16, []uint32{8448}
	case HighIL:
		return 16, []uint32{12288}
	case SystemIL:
		return 16, []uint32{16384}
	case ProtectedProcessIL:
		return 16, []uint32{20480}
	case CreatorOwner:
		return 3, []uint32{0}
	case CreatorGroup:
		return 3, []uint32{1}
	default:
		return 0, nil
	}
}

// SID returns the binary SID for this well-known identity.
func (w WellKnown) SID() wire.SID {
	auth, subs := w.parts()
	s, _ := wire.NewSID(auth, subs...) // the table is known-good
	return s
}

// String names the well-known identity.
func (w WellKnown) String() string {
	switch w {
	case Null:
		return "Null"
	case Everyone:
		return "Everyone"
	case Anonymous:
		return "Anonymous"
	case AuthenticatedUsers:
		return "Authenticated Users"
	case LocalSystem:
		return "LocalSystem"
	case LocalService:
		return "LocalService"
	case NetworkService:
		return "NetworkService"
	case BuiltinAdministrators:
		return `BUILTIN\Administrators`
	case BuiltinUsers:
		return `BUILTIN\Users`
	case UntrustedIL:
		return "Untrusted IL"
	case LowIL:
		return "Low IL"
	case MediumIL:
		return "Medium IL"
	case MediumPlusIL:
		return "Medium-Plus IL"
	case HighIL:
		return "High IL"
	case SystemIL:
		return "System IL"
	case ProtectedProcessIL:
		return "Protected-Process IL"
	case CreatorOwner:
		return "Creator Owner"
	case CreatorGroup:
		return "Creator Group"
	default:
		return "unknown well-known SID"
	}
}

// LookupWellKnown identifies sid as a well-known SID, reporting ok=false
// if it is not one.
func LookupWellKnown(sid wire.SID) (w WellKnown, ok bool) {
	for _, cand := range allWellKnown {
		if cand.SID() == sid { // wire.SID is comparable
			return cand, true
		}
	}
	return 0, false
}
