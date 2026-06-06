package sddl

import (
	"fmt"
	"strings"

	"github.com/peios/libp-go/sd"
	"github.com/peios/libp-go/wire"
)

// parser is a single-use SDDL recogniser over an input string.
type parser struct {
	in  string
	pos int
	opt options
}

func (p *parser) errf(off int, format string, args ...any) error {
	return &SyntaxError{Offset: off, Msg: fmt.Sprintf(format, args...)}
}

// parse recognises a whole SDDL descriptor.
func (p *parser) parse() (sd.Descriptor, error) {
	var d sd.Descriptor
	var seen [4]bool // O, G, D, S
	for p.pos < len(p.in) {
		off := p.pos
		if p.pos+1 >= len(p.in) || p.in[p.pos+1] != ':' {
			return sd.Descriptor{}, p.errf(off, "expected a component tag — O:, G:, D: or S:")
		}
		tag := p.in[p.pos]
		idx := strings.IndexByte("OGDS", tag)
		if idx < 0 {
			return sd.Descriptor{}, p.errf(off, "unknown component tag %q", string(tag))
		}
		if seen[idx] {
			return sd.Descriptor{}, p.errf(off, "duplicate %c: component", tag)
		}
		seen[idx] = true
		p.pos += 2

		var err error
		switch tag {
		case 'O':
			d.Owner, err = p.scanSID()
		case 'G':
			d.Group, err = p.scanSID()
		case 'D':
			err = p.scanACL(&d, false)
		case 'S':
			err = p.scanACL(&d, true)
		}
		if err != nil {
			return sd.Descriptor{}, err
		}
	}
	return d, nil
}

// scanSID consumes a SID token — an "S-1-…" literal or a two-letter
// alias — at the cursor and resolves it.
func (p *parser) scanSID() (wire.SID, error) {
	off := p.pos
	var text string
	if strings.HasPrefix(p.in[p.pos:], "S-") {
		t, err := p.scanRawSID()
		if err != nil {
			return wire.SID{}, err
		}
		text = t
	} else {
		if p.pos+2 > len(p.in) {
			return wire.SID{}, p.errf(off, "expected a SID")
		}
		text = p.in[p.pos : p.pos+2]
		p.pos += 2
	}
	s, err := p.opt.parseSIDText(text)
	if err != nil {
		return wire.SID{}, p.errf(off, "%s", err)
	}
	return s, nil
}

// scanRawSID consumes a leading "S-1-…" literal structurally — it stops
// at the first character that cannot continue the SID, so a following
// component tag is left for the caller.
func (p *parser) scanRawSID() (string, error) {
	start := p.pos
	if !strings.HasPrefix(p.in[p.pos:], "S-1-") {
		return "", p.errf(start, "expected a SID")
	}
	p.pos += 4
	if !p.scanNumber() {
		return "", p.errf(p.pos, "expected the SID identifier authority")
	}
	for p.pos < len(p.in) && p.in[p.pos] == '-' {
		p.pos++
		if !p.scanNumber() {
			return "", p.errf(p.pos, "expected a SID sub-authority")
		}
	}
	return p.in[start:p.pos], nil
}

// scanNumber consumes a decimal run, or an "0x"-prefixed hex run, and
// reports whether it consumed at least one digit.
func (p *parser) scanNumber() bool {
	start := p.pos
	if strings.HasPrefix(p.in[p.pos:], "0x") || strings.HasPrefix(p.in[p.pos:], "0X") {
		p.pos += 2
		for p.pos < len(p.in) && isHexDigit(p.in[p.pos]) {
			p.pos++
		}
		return p.pos > start+2
	}
	for p.pos < len(p.in) && p.in[p.pos] >= '0' && p.in[p.pos] <= '9' {
		p.pos++
	}
	return p.pos > start
}

// scanACL parses a D: or S: component — an optional flag run followed
// by zero or more ACEs — into the descriptor.
func (p *parser) scanACL(d *sd.Descriptor, isSACL bool) error {
	flagStart := p.pos
	for p.pos < len(p.in) {
		c := p.in[p.pos]
		if c == '(' {
			break
		}
		// A letter immediately followed by ':' starts the next component.
		if p.pos+1 < len(p.in) && p.in[p.pos+1] == ':' && isComponentTag(c) {
			break
		}
		if !isFlagChar(c) {
			return p.errf(p.pos, "unexpected %q in ACL flags", string(c))
		}
		p.pos++
	}
	flags := p.in[flagStart:p.pos]

	// NO_ACCESS_CONTROL is an explicit NULL ACL: the present bit stays
	// clear and the ACL pointer stays nil.
	if flags == "NO_ACCESS_CONTROL" {
		return nil
	}

	protected, autoInherited, autoInheritReq, err := parseACLFlags(flags)
	if err != nil {
		return p.errf(flagStart, "%s", err)
	}

	acl := &sd.ACL{}
	for p.pos < len(p.in) && p.in[p.pos] == '(' {
		ace, err := p.scanACE()
		if err != nil {
			return err
		}
		acl.Entries = append(acl.Entries, ace)
	}

	var control sd.Control
	if isSACL {
		control = sd.ControlSACLPresent
		if protected {
			control |= sd.ControlSACLProtected
		}
		if autoInherited {
			control |= sd.ControlSACLAutoInherited
		}
		if autoInheritReq {
			control |= controlSACLAutoInheritReq
		}
		d.SACL = acl
	} else {
		control = sd.ControlDACLPresent
		if protected {
			control |= sd.ControlDACLProtected
		}
		if autoInherited {
			control |= sd.ControlDACLAutoInherited
		}
		if autoInheritReq {
			control |= controlDACLAutoInheritReq
		}
		d.DACL = acl
	}
	d.Control |= control
	return nil
}

// parseACLFlags decodes the P / AI / AR flag run of an ACL.
func parseACLFlags(s string) (protected, autoInherited, autoInheritReq bool, err error) {
	for i := 0; i < len(s); {
		switch {
		case s[i] == 'P':
			protected = true
			i++
		case strings.HasPrefix(s[i:], "AI"):
			autoInherited = true
			i += 2
		case strings.HasPrefix(s[i:], "AR"):
			autoInheritReq = true
			i += 2
		default:
			return false, false, false, fmt.Errorf("unknown ACL flag at %q", s[i:])
		}
	}
	return protected, autoInherited, autoInheritReq, nil
}

// scanACE parses one parenthesised ACE at the cursor.
func (p *parser) scanACE() (sd.ACE, error) {
	open := p.pos
	depth := 0
	end := -1
	for i := p.pos; i < len(p.in); i++ {
		switch p.in[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				end = i
			}
		}
		if end >= 0 {
			break
		}
	}
	if end < 0 {
		return sd.ACE{}, p.errf(open, "unterminated ACE — missing ')'")
	}
	body := p.in[open+1 : end]
	p.pos = end + 1
	return parseACEBody(body, open+1, p.opt)
}

// parseACEBody decodes the ';'-delimited fields of an ACE and
// dispatches on the type. baseOff is the input offset of the body, for
// error positioning.
func parseACEBody(body string, baseOff int, opt options) (sd.ACE, error) {
	fields, offs := splitFields(body, baseOff)
	if len(fields) < 6 {
		return sd.ACE{}, &SyntaxError{Offset: baseOff,
			Msg: fmt.Sprintf("ACE has %d fields, want at least 6", len(fields))}
	}
	typeTag := fields[0]
	t, ok := aceTypeTags[typeTag]
	if !ok {
		return sd.ACE{}, &SyntaxError{Offset: offs[0],
			Msg: fmt.Sprintf("unknown ACE type %q", typeTag)}
	}
	if !aceTypeSupported(t) {
		return sd.ACE{}, &SyntaxError{Offset: offs[0],
			Msg: fmt.Sprintf("ACE type %q is not yet supported", typeTag)}
	}
	if isCallbackType(t) {
		return parseCallbackACE(t, typeTag, fields, offs, opt)
	}
	return parseStructuredACE(t, typeTag, fields, offs, opt)
}

// parseStructuredACE decodes a 6-field ACE — the allow / deny / audit /
// alarm, mandatory-label and object types.
func parseStructuredACE(t sd.AceType, typeTag string, fields []string, offs []int, opt options) (sd.ACE, error) {
	if len(fields) != 6 {
		return sd.ACE{}, &SyntaxError{Offset: offs[0],
			Msg: fmt.Sprintf("%s ACE has %d fields, want 6", typeTag, len(fields))}
	}
	flags, err := textToAceFlags(fields[1])
	if err != nil {
		return sd.ACE{}, &SyntaxError{Offset: offs[1], Msg: err.Error()}
	}
	mask, err := parseMask(fields[2])
	if err != nil {
		return sd.ACE{}, &SyntaxError{Offset: offs[2], Msg: err.Error()}
	}
	ace := sd.ACE{Type: t, Flags: flags, Mask: mask}

	if (fields[3] != "" || fields[4] != "") && !isObjectType(t) {
		return sd.ACE{}, &SyntaxError{Offset: offs[3],
			Msg: fmt.Sprintf("ACE type %q does not carry object-type GUIDs", typeTag)}
	}
	ace.ObjectType, ace.InheritedObjectType, err = parseGUIDFields(fields[3], fields[4], offs)
	if err != nil {
		return sd.ACE{}, err
	}

	if fields[5] == "" {
		return sd.ACE{}, &SyntaxError{Offset: offs[5], Msg: "ACE is missing its principal SID"}
	}
	sid, err := opt.parseSIDText(fields[5])
	if err != nil {
		return sd.ACE{}, &SyntaxError{Offset: offs[5], Msg: err.Error()}
	}
	ace.SID = sid
	return ace, nil
}

// parseCallbackACE decodes a 7-field callback (conditional) ACE — the
// SDDL XA / XD / XU / ZA types — whose final field is a conditional
// expression.
func parseCallbackACE(t sd.AceType, typeTag string, fields []string, offs []int, opt options) (sd.ACE, error) {
	if len(fields) != 7 {
		return sd.ACE{}, &SyntaxError{Offset: offs[0],
			Msg: fmt.Sprintf("%s ACE has %d fields, want 7", typeTag, len(fields))}
	}
	flags, err := textToAceFlags(fields[1])
	if err != nil {
		return sd.ACE{}, &SyntaxError{Offset: offs[1], Msg: err.Error()}
	}
	mask, err := parseMask(fields[2])
	if err != nil {
		return sd.ACE{}, &SyntaxError{Offset: offs[2], Msg: err.Error()}
	}
	objType, inhType, err := parseGUIDFields(fields[3], fields[4], offs)
	if err != nil {
		return sd.ACE{}, err
	}
	if (objType != nil || inhType != nil) && t != sd.AceAccessAllowedCallbackObject {
		return sd.ACE{}, &SyntaxError{Offset: offs[3],
			Msg: fmt.Sprintf("ACE type %q does not carry object-type GUIDs", typeTag)}
	}
	if fields[5] == "" {
		return sd.ACE{}, &SyntaxError{Offset: offs[5], Msg: "ACE is missing its principal SID"}
	}
	sid, err := opt.parseSIDText(fields[5])
	if err != nil {
		return sd.ACE{}, &SyntaxError{Offset: offs[5], Msg: err.Error()}
	}
	cond, err := parseConditionText(fields[6], opt)
	if err != nil {
		return sd.ACE{}, &SyntaxError{Offset: offs[6], Msg: "conditional expression: " + err.Error()}
	}

	var ace sd.ACE
	switch t {
	case sd.AceAccessAllowedCallback:
		ace = sd.AllowCallback(sid, mask, cond)
	case sd.AceAccessDeniedCallback:
		ace = sd.DenyCallback(sid, mask, cond)
	case sd.AceSystemAuditCallback:
		ace = sd.AuditCallback(sid, mask, cond)
	case sd.AceAccessAllowedCallbackObject:
		ace = sd.AllowCallbackObject(sid, mask, objType, inhType, cond)
	}
	ace.Flags = flags
	return ace, nil
}

// parseGUIDFields decodes the object-type and inherited-object-type
// GUID fields of an ACE; an empty field yields a nil GUID.
func parseGUIDFields(objField, inhField string, offs []int) (objType, inhType *sd.GUID, err error) {
	if objField != "" {
		g, e := parseGUID(objField)
		if e != nil {
			return nil, nil, &SyntaxError{Offset: offs[3], Msg: e.Error()}
		}
		objType = &g
	}
	if inhField != "" {
		g, e := parseGUID(inhField)
		if e != nil {
			return nil, nil, &SyntaxError{Offset: offs[4], Msg: e.Error()}
		}
		inhType = &g
	}
	return objType, inhType, nil
}

// splitFields splits an ACE body on top-level ';' — parens are honoured
// so a trailing conditional clause stays one field — and reports the
// input offset of each field.
func splitFields(body string, baseOff int) (fields []string, offs []int) {
	depth := 0
	start := 0
	for i := 0; i < len(body); i++ {
		switch body[i] {
		case '(':
			depth++
		case ')':
			depth--
		case ';':
			if depth == 0 {
				fields = append(fields, body[start:i])
				offs = append(offs, baseOff+start)
				start = i + 1
			}
		}
	}
	fields = append(fields, body[start:])
	offs = append(offs, baseOff+start)
	return fields, offs
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func isComponentTag(c byte) bool {
	return c == 'O' || c == 'G' || c == 'D' || c == 'S'
}

func isFlagChar(c byte) bool {
	return (c >= 'A' && c <= 'Z') || c == '_'
}
