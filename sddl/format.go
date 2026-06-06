package sddl

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/peios/libp-go/sd"
	"github.com/peios/libp-go/wire"
	uapi "github.com/peios/pkm/uapi/go"
)

// formatDescriptor renders a descriptor as an SDDL string.
func formatDescriptor(d sd.Descriptor, opt options) (string, error) {
	var b strings.Builder
	if d.Owner.IsValid() {
		b.WriteString("O:")
		b.WriteString(opt.formatSID(d.Owner))
	}
	if d.Group.IsValid() {
		b.WriteString("G:")
		b.WriteString(opt.formatSID(d.Group))
	}
	if d.DACL != nil {
		b.WriteString("D:")
		b.WriteString(formatACLFlags(d.Control, false))
		if err := formatACEs(&b, d.DACL.Entries, opt); err != nil {
			return "", err
		}
	}
	if d.SACL != nil {
		b.WriteString("S:")
		b.WriteString(formatACLFlags(d.Control, true))
		if err := formatACEs(&b, d.SACL.Entries, opt); err != nil {
			return "", err
		}
	}
	return b.String(), nil
}

// formatACLFlags renders the P / AR / AI flag run for one ACL.
func formatACLFlags(c sd.Control, isSACL bool) string {
	protected, autoInherited, autoInheritReq := sd.ControlDACLProtected,
		sd.ControlDACLAutoInherited, controlDACLAutoInheritReq
	if isSACL {
		protected, autoInherited, autoInheritReq = sd.ControlSACLProtected,
			sd.ControlSACLAutoInherited, controlSACLAutoInheritReq
	}
	var s strings.Builder
	if c&protected != 0 {
		s.WriteString("P")
	}
	if c&autoInheritReq != 0 {
		s.WriteString("AR")
	}
	if c&autoInherited != 0 {
		s.WriteString("AI")
	}
	return s.String()
}

func formatACEs(b *strings.Builder, aces []sd.ACE, opt options) error {
	for i := range aces {
		s, err := formatACE(aces[i], opt)
		if err != nil {
			return fmt.Errorf("libp/sddl: ACE %d: %w", i, err)
		}
		b.WriteString(s)
	}
	return nil
}

// formatACE renders one ACE as a parenthesised SDDL clause.
func formatACE(a sd.ACE, opt options) (string, error) {
	tag, ok := aceTagByType[a.Type]
	if !ok {
		return "", fmt.Errorf("ACE type 0x%02x has no SDDL tag", byte(a.Type))
	}
	if !aceTypeSupported(a.Type) {
		return "", fmt.Errorf("ACE type %q is not yet supported", tag)
	}
	if a.Flags&^knownAceFlags != 0 {
		return "", fmt.Errorf("ACE carries flag bits %#x with no SDDL representation",
			uint8(a.Flags&^knownAceFlags))
	}
	if isCallbackType(a.Type) {
		return formatCallbackACE(a, tag, opt)
	}
	var objGUID, inhGUID string
	if a.ObjectType != nil {
		objGUID = formatGUID(*a.ObjectType)
	}
	if a.InheritedObjectType != nil {
		inhGUID = formatGUID(*a.InheritedObjectType)
	}
	return fmt.Sprintf("(%s;%s;%s;%s;%s;%s)",
		tag,
		aceFlagsToText(a.Flags),
		formatMask(a.Mask),
		objGUID,
		inhGUID,
		opt.formatSID(a.SID),
	), nil
}

// formatCallbackACE renders a callback (conditional) ACE. Its Raw body
// is mask + [object header] + SID + the artx-encoded condition.
func formatCallbackACE(a sd.ACE, tag string, opt options) (string, error) {
	body := a.Raw
	if len(body) < 4 {
		return "", fmt.Errorf("%s ACE body is too short", tag)
	}
	mask := binary.LittleEndian.Uint32(body[:4])
	off := 4

	var objGUID, inhGUID string
	if a.Type == sd.AceAccessAllowedCallbackObject {
		if len(body) < 8 {
			return "", fmt.Errorf("%s ACE body is too short", tag)
		}
		present := binary.LittleEndian.Uint32(body[4:8])
		off = 8
		if present&uapi.KACS_ACE_OBJECT_TYPE_PRESENT != 0 {
			g, err := guidAt(body, off, tag)
			if err != nil {
				return "", err
			}
			objGUID = formatGUID(g)
			off += 16
		}
		if present&uapi.KACS_ACE_INHERITED_OBJECT_TYPE_PRESENT != 0 {
			g, err := guidAt(body, off, tag)
			if err != nil {
				return "", err
			}
			inhGUID = formatGUID(g)
			off += 16
		}
	}

	if off > len(body) {
		return "", fmt.Errorf("%s ACE body is too short", tag)
	}
	sid, err := wire.ParseSID(body[off:])
	if err != nil {
		return "", fmt.Errorf("%s ACE: %w", tag, err)
	}
	off += len(sid.Bytes())
	if off > len(body) {
		return "", fmt.Errorf("%s ACE body is too short", tag)
	}
	condText, err := decodeCondition(body[off:], opt)
	if err != nil {
		return "", fmt.Errorf("%s ACE: %w", tag, err)
	}
	return fmt.Sprintf("(%s;%s;%s;%s;%s;%s;(%s))",
		tag, aceFlagsToText(a.Flags), formatMask(mask),
		objGUID, inhGUID, opt.formatSID(sid), condText), nil
}

// guidAt reads a 16-byte GUID from body at off.
func guidAt(body []byte, off int, tag string) (sd.GUID, error) {
	var g sd.GUID
	if off+16 > len(body) {
		return g, fmt.Errorf("%s ACE body is too short", tag)
	}
	copy(g[:], body[off:off+16])
	return g, nil
}
