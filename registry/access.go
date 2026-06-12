package registry

import uapi "github.com/peios/pkm/uapi/go"

// Access is an LCS key access mask — the set of rights an open requests,
// and the granted mask the kernel stores on the fd (PSD-005 §3.1). Values
// combine with bitwise OR.
type Access uint32

// Specific registry rights — the low 16 bits of a key access mask, from
// pkm via the uapi binding.
const (
	QueryValue       Access = uapi.KEY_QUERY_VALUE        // read values
	SetValue         Access = uapi.KEY_SET_VALUE          // write and delete values
	CreateSubKey     Access = uapi.KEY_CREATE_SUB_KEY     // create child keys
	EnumerateSubKeys Access = uapi.KEY_ENUMERATE_SUB_KEYS // enumerate child keys
	Notify           Access = uapi.KEY_NOTIFY             // subscribe to change watches
	CreateLink       Access = uapi.KEY_CREATE_LINK        // create symlink keys (also needs SeTcbPrivilege)
)

// Standard and special rights — fixed MS-DTYP bit positions shared across
// KACS object types, from the uapi binding.
const (
	Delete               Access = uapi.KACS_ACCESS_DELETE                 // delete or hide the key
	ReadControl          Access = uapi.KACS_ACCESS_READ_CONTROL           // read the SD and key metadata
	WriteDAC             Access = uapi.KACS_ACCESS_WRITE_DAC              // modify the DACL
	WriteOwner           Access = uapi.KACS_ACCESS_WRITE_OWNER            // change the owner SID
	AccessSystemSecurity Access = uapi.KACS_ACCESS_ACCESS_SYSTEM_SECURITY // read/modify the SACL (gated by SeSecurityPrivilege)
	// MaximumAllowed requests whatever the key's SD grants; the granted
	// mask is the full allowed set computed by AccessCheck.
	MaximumAllowed Access = uapi.KACS_ACCESS_MAXIMUM_ALLOWED
)

// Concrete convenience masks (PSD-005 §3.1).
const (
	// Read is QueryValue | EnumerateSubKeys | Notify | ReadControl.
	Read Access = uapi.KEY_READ
	// Write is SetValue | CreateSubKey | ReadControl.
	Write Access = uapi.KEY_WRITE
	// AllAccess is every specific right plus every standard right.
	AllAccess Access = uapi.KEY_ALL_ACCESS
)

// bits is the raw bitmask value.
func (a Access) bits() uint32 { return uint32(a) }

// Contains reports whether every right in other is present in this mask.
func (a Access) Contains(other Access) bool { return a&other == other }
