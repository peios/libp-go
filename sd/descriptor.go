package sd

import (
	"encoding/binary"
	"errors"

	"github.com/peios/libp-go/wire"
	uapi "github.com/peios/pkm/uapi/go"
)

// ErrBadSD reports a buffer that is not a well-formed security descriptor.
var ErrBadSD = errors.New("libp/sd: malformed security descriptor")

// sdHeaderBytes is the byte length of a self-relative SD header.
const sdHeaderBytes = uapi.KACS_SD_HEADER_BYTES

// Standard and generic access-mask bits (MS-DTYP 2.4.3). An ACE mask
// also carries object-class-specific rights in its low 16 bits, so ACE
// masks are plain uint32 rather than a single named type.
const (
	AccessDelete         uint32 = uapi.KACS_ACCESS_DELETE
	AccessReadControl    uint32 = uapi.KACS_ACCESS_READ_CONTROL
	AccessWriteDAC       uint32 = uapi.KACS_ACCESS_WRITE_DAC
	AccessWriteOwner     uint32 = uapi.KACS_ACCESS_WRITE_OWNER
	AccessSynchronize    uint32 = uapi.KACS_ACCESS_SYNCHRONIZE
	AccessSystemSecurity uint32 = uapi.KACS_ACCESS_ACCESS_SYSTEM_SECURITY
	AccessMaximumAllowed uint32 = uapi.KACS_ACCESS_MAXIMUM_ALLOWED
	GenericAll           uint32 = uapi.KACS_ACCESS_GENERIC_ALL
	GenericExecute       uint32 = uapi.KACS_ACCESS_GENERIC_EXECUTE
	GenericWrite         uint32 = uapi.KACS_ACCESS_GENERIC_WRITE
	GenericRead          uint32 = uapi.KACS_ACCESS_GENERIC_READ
)

// Control is the SECURITY_DESCRIPTOR control word.
type Control uint16

const (
	ControlOwnerDefaulted    Control = uapi.KACS_SD_OWNER_DEFAULTED
	ControlGroupDefaulted    Control = uapi.KACS_SD_GROUP_DEFAULTED
	ControlDACLPresent       Control = uapi.KACS_SD_DACL_PRESENT
	ControlDACLDefaulted     Control = uapi.KACS_SD_DACL_DEFAULTED
	ControlSACLPresent       Control = uapi.KACS_SD_SACL_PRESENT
	ControlSACLDefaulted     Control = uapi.KACS_SD_SACL_DEFAULTED
	ControlDACLAutoInherited Control = uapi.KACS_SD_DACL_AUTO_INHERITED
	ControlSACLAutoInherited Control = uapi.KACS_SD_SACL_AUTO_INHERITED
	ControlDACLProtected     Control = uapi.KACS_SD_DACL_PROTECTED
	ControlSACLProtected     Control = uapi.KACS_SD_SACL_PROTECTED
	ControlSelfRelative      Control = uapi.KACS_SD_SELF_RELATIVE
)

// Descriptor is a security descriptor: an owner, a group, a DACL, and a
// SACL, plus a control word.
//
// Owner / Group are wire.SIDs; the zero SID means absent. DACL / SACL
// are *ACL; nil means absent (a NULL DACL grants implicit full access),
// while a non-nil — even empty — ACL means present. Marshal always
// emits the self-relative form and sets the *Present control bits.
type Descriptor struct {
	Control Control
	Owner   wire.SID
	Group   wire.SID
	DACL    *ACL
	SACL    *ACL
}

// Marshal emits the self-relative security-descriptor wire bytes: a
// 20-byte header followed by the owner, group, SACL, and DACL.
func (d Descriptor) Marshal() ([]byte, error) {
	out := make([]byte, sdHeaderBytes)
	control := d.Control | ControlSelfRelative
	var ownerOff, groupOff, saclOff, daclOff uint32

	if d.Owner.IsValid() {
		ownerOff = uint32(len(out))
		out = append(out, d.Owner.Bytes()...)
	}
	if d.Group.IsValid() {
		groupOff = uint32(len(out))
		out = append(out, d.Group.Bytes()...)
	}
	if d.SACL != nil {
		control |= ControlSACLPresent
		b, err := d.SACL.Marshal()
		if err != nil {
			return nil, err
		}
		saclOff = uint32(len(out))
		out = append(out, b...)
	}
	if d.DACL != nil {
		control |= ControlDACLPresent
		b, err := d.DACL.Marshal()
		if err != nil {
			return nil, err
		}
		daclOff = uint32(len(out))
		out = append(out, b...)
	}

	out[0] = 1 // revision
	binary.LittleEndian.PutUint16(out[2:], uint16(control))
	binary.LittleEndian.PutUint32(out[4:], ownerOff)
	binary.LittleEndian.PutUint32(out[8:], groupOff)
	binary.LittleEndian.PutUint32(out[12:], saclOff)
	binary.LittleEndian.PutUint32(out[16:], daclOff)
	return out, nil
}

// ParseDescriptor decodes a self-relative security descriptor.
func ParseDescriptor(buf []byte) (Descriptor, error) {
	if len(buf) < sdHeaderBytes {
		return Descriptor{}, ErrBadSD
	}
	d := Descriptor{Control: Control(binary.LittleEndian.Uint16(buf[2:4]))}
	ownerOff := binary.LittleEndian.Uint32(buf[4:8])
	groupOff := binary.LittleEndian.Uint32(buf[8:12])
	saclOff := binary.LittleEndian.Uint32(buf[12:16])
	daclOff := binary.LittleEndian.Uint32(buf[16:20])

	if ownerOff != 0 {
		s, err := sidAt(buf, ownerOff)
		if err != nil {
			return Descriptor{}, err
		}
		d.Owner = s
	}
	if groupOff != 0 {
		s, err := sidAt(buf, groupOff)
		if err != nil {
			return Descriptor{}, err
		}
		d.Group = s
	}
	if d.Control&ControlDACLPresent != 0 && daclOff != 0 {
		acl, err := aclAt(buf, daclOff)
		if err != nil {
			return Descriptor{}, err
		}
		d.DACL = &acl
	}
	if d.Control&ControlSACLPresent != 0 && saclOff != 0 {
		acl, err := aclAt(buf, saclOff)
		if err != nil {
			return Descriptor{}, err
		}
		d.SACL = &acl
	}
	return d, nil
}

func sidAt(buf []byte, off uint32) (wire.SID, error) {
	if int(off) >= len(buf) {
		return wire.SID{}, ErrBadSD
	}
	return wire.ParseSID(buf[off:])
}

func aclAt(buf []byte, off uint32) (ACL, error) {
	if int(off) >= len(buf) {
		return ACL{}, ErrBadSD
	}
	return ParseACL(buf[off:])
}
