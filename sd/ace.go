package sd

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/peios/libp-go/wire"
	uapi "github.com/peios/pkm/uapi/go"
)

// ErrBadACE reports a buffer that is not a well-formed ACE.
var ErrBadACE = errors.New("libp/sd: malformed ACE")

// AceType is an ACE's type byte (MS-DTYP 2.4.4.1).
type AceType uint8

const (
	AceAccessAllowed               AceType = uapi.KACS_ACE_TYPE_ACCESS_ALLOWED
	AceAccessDenied                AceType = uapi.KACS_ACE_TYPE_ACCESS_DENIED
	AceSystemAudit                 AceType = uapi.KACS_ACE_TYPE_SYSTEM_AUDIT
	AceSystemAlarm                 AceType = uapi.KACS_ACE_TYPE_SYSTEM_ALARM
	AceAccessAllowedCompound       AceType = uapi.KACS_ACE_TYPE_ACCESS_ALLOWED_COMPOUND
	AceAccessAllowedObject         AceType = uapi.KACS_ACE_TYPE_ACCESS_ALLOWED_OBJECT
	AceAccessDeniedObject          AceType = uapi.KACS_ACE_TYPE_ACCESS_DENIED_OBJECT
	AceSystemAuditObject           AceType = uapi.KACS_ACE_TYPE_SYSTEM_AUDIT_OBJECT
	AceSystemAlarmObject           AceType = uapi.KACS_ACE_TYPE_SYSTEM_ALARM_OBJECT
	AceAccessAllowedCallback       AceType = uapi.KACS_ACE_TYPE_ACCESS_ALLOWED_CALLBACK
	AceAccessDeniedCallback        AceType = uapi.KACS_ACE_TYPE_ACCESS_DENIED_CALLBACK
	AceAccessAllowedCallbackObject AceType = uapi.KACS_ACE_TYPE_ACCESS_ALLOWED_CALLBACK_OBJECT
	AceAccessDeniedCallbackObject  AceType = uapi.KACS_ACE_TYPE_ACCESS_DENIED_CALLBACK_OBJECT
	AceSystemAuditCallback         AceType = uapi.KACS_ACE_TYPE_SYSTEM_AUDIT_CALLBACK
	AceSystemAlarmCallback         AceType = uapi.KACS_ACE_TYPE_SYSTEM_ALARM_CALLBACK
	AceSystemAuditCallbackObject   AceType = uapi.KACS_ACE_TYPE_SYSTEM_AUDIT_CALLBACK_OBJECT
	AceSystemAlarmCallbackObject   AceType = uapi.KACS_ACE_TYPE_SYSTEM_ALARM_CALLBACK_OBJECT
	AceSystemMandatoryLabel        AceType = uapi.KACS_ACE_TYPE_SYSTEM_MANDATORY_LABEL
	AceSystemResourceAttribute     AceType = uapi.KACS_ACE_TYPE_SYSTEM_RESOURCE_ATTRIBUTE
	AceSystemScopedPolicyID        AceType = uapi.KACS_ACE_TYPE_SYSTEM_SCOPED_POLICY_ID
	AceSystemProcessTrustLabel     AceType = uapi.KACS_ACE_TYPE_SYSTEM_PROCESS_TRUST_LABEL
	AceSystemAccessFilter          AceType = uapi.KACS_ACE_TYPE_SYSTEM_ACCESS_FILTER
)

// isSimpleMaskSID reports whether the ACE body is "u32 mask, then SID".
func (t AceType) isSimpleMaskSID() bool {
	switch t {
	case AceAccessAllowed, AceAccessDenied, AceSystemAudit, AceSystemAlarm,
		AceSystemMandatoryLabel:
		return true
	default:
		return false
	}
}

// isObject reports whether the ACE body is the object layout — mask,
// GUID-presence flags, the present GUIDs, then SID.
func (t AceType) isObject() bool {
	switch t {
	case AceAccessAllowedObject, AceAccessDeniedObject, AceSystemAuditObject,
		AceSystemAlarmObject:
		return true
	default:
		return false
	}
}

// needsDSRevision reports whether an ACL containing this ACE must use
// the directory-services ACL revision (object-type and callback types).
func (t AceType) needsDSRevision() bool {
	return t >= 0x05 && t <= 0x10
}

// AceFlags is an ACE's flags byte — inheritance and audit control.
type AceFlags uint8

const (
	FlagObjectInherit      AceFlags = uapi.KACS_ACE_FLAG_OBJECT_INHERIT
	FlagContainerInherit   AceFlags = uapi.KACS_ACE_FLAG_CONTAINER_INHERIT
	FlagNoPropagateInherit AceFlags = uapi.KACS_ACE_FLAG_NO_PROPAGATE_INHERIT
	FlagInheritOnly        AceFlags = uapi.KACS_ACE_FLAG_INHERIT_ONLY
	FlagInherited          AceFlags = uapi.KACS_ACE_FLAG_INHERITED
	FlagSuccessfulAccess   AceFlags = uapi.KACS_ACE_FLAG_SUCCESSFUL_ACCESS
	FlagFailedAccess       AceFlags = uapi.KACS_ACE_FLAG_FAILED_ACCESS
)

// GUID is a 16-byte object identifier used by object ACEs.
type GUID [16]byte

// ACE is one access-control entry. Type selects which fields are
// meaningful: the allow/deny/audit/alarm and mandatory-label types use
// Mask + SID; the object types add ObjectType / InheritedObjectType.
//
// Raw carries the verbatim ACE body for types this struct does not model
// structurally — callback (conditional) ACEs, resource-attribute ACEs,
// and the exotic system types. When Raw is non-nil it is emitted as-is
// and the structured fields are ignored. (Typed callback / claim
// constructors arrive with the conditions + claims sub-chunk.)
type ACE struct {
	Type                AceType
	Flags               AceFlags
	Mask                uint32
	SID                 wire.SID
	ObjectType          *GUID
	InheritedObjectType *GUID
	Raw                 []byte
}

// Allow grants mask to sid.
func Allow(sid wire.SID, mask uint32) ACE {
	return ACE{Type: AceAccessAllowed, Mask: mask, SID: sid}
}

// Deny denies mask to sid.
func Deny(sid wire.SID, mask uint32) ACE {
	return ACE{Type: AceAccessDenied, Mask: mask, SID: sid}
}

// Audit records access to mask by sid. Pair with FlagSuccessfulAccess
// and/or FlagFailedAccess.
func Audit(sid wire.SID, mask uint32) ACE {
	return ACE{Type: AceSystemAudit, Mask: mask, SID: sid}
}

// MandatoryLabel sets an integrity-level label. policy carries the
// mandatory-policy bits; integrityLevel is the integrity-level SID.
func MandatoryLabel(integrityLevel wire.SID, policy uint32) ACE {
	return ACE{Type: AceSystemMandatoryLabel, Mask: policy, SID: integrityLevel}
}

// AllowObject grants mask to sid, optionally scoped to an object type
// and/or inherited object type. A nil GUID is omitted from the ACE.
func AllowObject(sid wire.SID, mask uint32, objectType, inheritedObjectType *GUID) ACE {
	return ACE{
		Type: AceAccessAllowedObject, Mask: mask, SID: sid,
		ObjectType: objectType, InheritedObjectType: inheritedObjectType,
	}
}

// DenyObject denies mask to sid. See AllowObject.
func DenyObject(sid wire.SID, mask uint32, objectType, inheritedObjectType *GUID) ACE {
	return ACE{
		Type: AceAccessDeniedObject, Mask: mask, SID: sid,
		ObjectType: objectType, InheritedObjectType: inheritedObjectType,
	}
}

// AuditObject records object-scoped access. See AllowObject.
func AuditObject(sid wire.SID, mask uint32, objectType, inheritedObjectType *GUID) ACE {
	return ACE{
		Type: AceSystemAuditObject, Mask: mask, SID: sid,
		ObjectType: objectType, InheritedObjectType: inheritedObjectType,
	}
}

// RawACE builds an ACE of the given type carrying body verbatim — the
// bytes after the 4-byte ACE header. The escape hatch for ACE types
// without a typed constructor.
func RawACE(t AceType, body []byte) ACE {
	return ACE{Type: t, Raw: append([]byte(nil), body...)}
}

// objectBody assembles an object-ACE body: the mask, the GUID-presence
// flags, the present GUIDs, then the SID.
func objectBody(mask uint32, objectType, inheritedObjectType *GUID, sid wire.SID) []byte {
	var present uint32
	if objectType != nil {
		present |= uapi.KACS_ACE_OBJECT_TYPE_PRESENT
	}
	if inheritedObjectType != nil {
		present |= uapi.KACS_ACE_INHERITED_OBJECT_TYPE_PRESENT
	}
	b := binary.LittleEndian.AppendUint32(nil, mask)
	b = binary.LittleEndian.AppendUint32(b, present)
	if objectType != nil {
		b = append(b, objectType[:]...)
	}
	if inheritedObjectType != nil {
		b = append(b, inheritedObjectType[:]...)
	}
	return append(b, sid.Bytes()...)
}

// callbackBody assembles a non-object callback ACE body: mask, SID, then
// the encoded conditional expression.
func callbackBody(mask uint32, sid wire.SID, cond Condition) []byte {
	b := binary.LittleEndian.AppendUint32(nil, mask)
	b = append(b, sid.Bytes()...)
	return append(b, cond.Encode()...)
}

// AllowCallback grants mask to sid when cond evaluates true at access
// time. (Parsed back, a callback ACE round-trips through the Raw field —
// typed decode of conditional expressions pairs with the SDDL follow-on.)
func AllowCallback(sid wire.SID, mask uint32, cond Condition) ACE {
	return ACE{Type: AceAccessAllowedCallback, Raw: callbackBody(mask, sid, cond)}
}

// DenyCallback denies mask to sid when cond evaluates true.
func DenyCallback(sid wire.SID, mask uint32, cond Condition) ACE {
	return ACE{Type: AceAccessDeniedCallback, Raw: callbackBody(mask, sid, cond)}
}

// AuditCallback records access to mask by sid when cond evaluates true.
func AuditCallback(sid wire.SID, mask uint32, cond Condition) ACE {
	return ACE{Type: AceSystemAuditCallback, Raw: callbackBody(mask, sid, cond)}
}

// AllowCallbackObject is AllowCallback additionally scoped by object-type
// and/or inherited-object-type GUIDs.
func AllowCallbackObject(sid wire.SID, mask uint32, objectType, inheritedObjectType *GUID, cond Condition) ACE {
	body := append(objectBody(mask, objectType, inheritedObjectType, sid), cond.Encode()...)
	return ACE{Type: AceAccessAllowedCallbackObject, Raw: body}
}

// DenyCallbackObject is DenyCallback scoped by object-type GUIDs.
func DenyCallbackObject(sid wire.SID, mask uint32, objectType, inheritedObjectType *GUID, cond Condition) ACE {
	body := append(objectBody(mask, objectType, inheritedObjectType, sid), cond.Encode()...)
	return ACE{Type: AceAccessDeniedCallbackObject, Raw: body}
}

// AuditCallbackObject is AuditCallback scoped by object-type GUIDs.
func AuditCallbackObject(sid wire.SID, mask uint32, objectType, inheritedObjectType *GUID, cond Condition) ACE {
	body := append(objectBody(mask, objectType, inheritedObjectType, sid), cond.Encode()...)
	return ACE{Type: AceSystemAuditCallbackObject, Raw: body}
}

// ResourceAttribute builds a resource-attribute ACE exposing claim for
// conditional-ACE evaluation. The principal SID is fixed to Everyone, as
// the format requires. It fails if claim cannot be encoded.
func ResourceAttribute(claim Claim) (ACE, error) {
	entry, err := claim.Encode()
	if err != nil {
		return ACE{}, err
	}
	body := binary.LittleEndian.AppendUint32(nil, 0) // Mask — reserved
	body = append(body, Everyone.SID().Bytes()...)
	body = append(body, entry...)
	return ACE{Type: AceSystemResourceAttribute, Raw: body}, nil
}

// body assembles the ACE body — everything after the 4-byte header.
func (a ACE) body() ([]byte, error) {
	if a.Raw != nil {
		return a.Raw, nil
	}
	switch {
	case a.Type.isObject():
		return objectBody(a.Mask, a.ObjectType, a.InheritedObjectType, a.SID), nil
	case a.Type.isSimpleMaskSID():
		b := binary.LittleEndian.AppendUint32(nil, a.Mask)
		return append(b, a.SID.Bytes()...), nil
	default:
		return nil, fmt.Errorf("libp/sd: ACE type 0x%02x has no structured encoding — use RawACE", byte(a.Type))
	}
}

// Marshal emits the ACE's wire bytes: a 4-byte header then the body.
func (a ACE) Marshal() ([]byte, error) {
	body, err := a.body()
	if err != nil {
		return nil, err
	}
	size := 4 + len(body)
	if size > 0xFFFF {
		return nil, fmt.Errorf("libp/sd: ACE size %d exceeds 65535", size)
	}
	out := make([]byte, 4, size)
	out[0] = byte(a.Type)
	out[1] = byte(a.Flags)
	binary.LittleEndian.PutUint16(out[2:], uint16(size))
	return append(out, body...), nil
}

// ParseACE decodes one ACE from the start of buf, returning the ACE and
// the number of bytes it occupied.
func ParseACE(buf []byte) (ACE, int, error) {
	if len(buf) < 4 {
		return ACE{}, 0, ErrBadACE
	}
	size := int(binary.LittleEndian.Uint16(buf[2:4]))
	if size < 4 || size > len(buf) {
		return ACE{}, 0, ErrBadACE
	}
	a := ACE{Type: AceType(buf[0]), Flags: AceFlags(buf[1])}
	body := buf[4:size]

	switch {
	case a.Type.isSimpleMaskSID():
		if len(body) < 4 {
			return ACE{}, 0, ErrBadACE
		}
		a.Mask = binary.LittleEndian.Uint32(body)
		sid, err := wire.ParseSID(body[4:])
		if err != nil {
			return ACE{}, 0, fmt.Errorf("libp/sd: ACE: %w", err)
		}
		a.SID = sid
	case a.Type.isObject():
		if len(body) < 8 {
			return ACE{}, 0, ErrBadACE
		}
		a.Mask = binary.LittleEndian.Uint32(body)
		present := binary.LittleEndian.Uint32(body[4:])
		off := 8
		if present&uapi.KACS_ACE_OBJECT_TYPE_PRESENT != 0 {
			if len(body) < off+16 {
				return ACE{}, 0, ErrBadACE
			}
			var g GUID
			copy(g[:], body[off:off+16])
			a.ObjectType = &g
			off += 16
		}
		if present&uapi.KACS_ACE_INHERITED_OBJECT_TYPE_PRESENT != 0 {
			if len(body) < off+16 {
				return ACE{}, 0, ErrBadACE
			}
			var g GUID
			copy(g[:], body[off:off+16])
			a.InheritedObjectType = &g
			off += 16
		}
		sid, err := wire.ParseSID(body[off:])
		if err != nil {
			return ACE{}, 0, fmt.Errorf("libp/sd: ACE: %w", err)
		}
		a.SID = sid
	default:
		a.Raw = append([]byte(nil), body...)
	}
	return a, size, nil
}
