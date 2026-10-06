package sd

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"unicode/utf8"

	"github.com/peios/libp-go/wire"
	uapi "github.com/peios/pkm/uapi/go"
)

// ErrBadAuditContext reports an audit context the kernel would refuse,
// or one EncodeAuditContext will not write.
var ErrBadAuditContext = errors.New("libp/sd: malformed audit context")

// An audit context names the object a daemon guards, so the kernel's
// audit record of an access check says what was decided on (PGSS §6.7).
// It is one MessagePack map,
//
//	{kind: "service", service: {name: "jellyfin"}}
//
// which the kernel copies into kacs.audit.access.checked as object.kind
// and object.<kind>.*, marking the record fields.attestation.userspace.
// It refuses any other shape with EINVAL. Pass the encoded bytes as
// CheckRequest.AuditContext.

// auditKind is the variant tag of an AuditField.
type auditKind uint8

const (
	auditStr auditKind = iota
	auditUint
	auditInt
	auditBool
	auditBin
)

// AuditField is one identifying field of an audited object, written as
// object.<kind>.<key>. Build fields with the constructors below. A value
// is a scalar in one of the PGSS §6.5 wire forms; there is no nil, since
// a field with no value is left out.
type AuditField struct {
	key  string
	kind auditKind
	u64  uint64
	i64  int64
	b    bool
	data []byte
}

// AuditString, AuditUint, AuditInt, AuditBool, AuditBytes and AuditSID
// build the field kinds. AuditSID writes the SID in its binary form.
func AuditString(key, v string) AuditField {
	return AuditField{key: key, kind: auditStr, data: []byte(v)}
}
func AuditUint(key string, v uint64) AuditField { return AuditField{key: key, kind: auditUint, u64: v} }
func AuditInt(key string, v int64) AuditField   { return AuditField{key: key, kind: auditInt, i64: v} }
func AuditBool(key string, v bool) AuditField   { return AuditField{key: key, kind: auditBool, b: v} }
func AuditBytes(key string, v []byte) AuditField {
	return AuditField{key: key, kind: auditBin, data: v}
}
func AuditSID(key string, sid wire.SID) AuditField {
	return AuditField{key: key, kind: auditBin, data: sid.Bytes()}
}

// auditContextMaxDepth is the nesting the kernel allows an audit
// context: the emit limit less the record's object map it lands in.
const auditContextMaxDepth = uapi.KMES_CONFIG_MAX_NESTING_DEPTH_DEFAULT - 1

// EncodeAuditContext encodes the audit context naming an object of kind
// kind by fields, in order; with no fields it is {kind: kind}.
//
// kind and every key are one kebab-case event-name segment,
// [a-z][a-z0-9]*(-[a-z0-9]+)*, and each key appears once, since a
// repeated key would make object.<kind>.<key> ambiguous. A string value
// is UTF-8, and the whole context is at most
// KACS_ACCESS_CHECK_MAX_AUDIT_CONTEXT_LEN bytes. Anything else fails
// with ErrBadAuditContext.
func EncodeAuditContext(kind string, fields ...AuditField) ([]byte, error) {
	if !isEventSegment([]byte(kind)) {
		return nil, fmt.Errorf("libp/sd: audit context kind %q is not a segment: %w", kind, ErrBadAuditContext)
	}
	seen := make(map[string]bool, len(fields))
	for _, f := range fields {
		if !isEventSegment([]byte(f.key)) {
			return nil, fmt.Errorf("libp/sd: audit field %q is not a segment: %w", f.key, ErrBadAuditContext)
		}
		if seen[f.key] {
			return nil, fmt.Errorf("libp/sd: audit field %q given twice: %w", f.key, ErrBadAuditContext)
		}
		seen[f.key] = true
		if f.kind == auditStr && !utf8.Valid(f.data) {
			return nil, fmt.Errorf("libp/sd: audit field %q is not UTF-8: %w", f.key, ErrBadAuditContext)
		}
	}

	var out []byte
	if len(fields) == 0 {
		out = mpMap(out, 1)
	} else {
		out = mpMap(out, 2)
	}
	out = mpStr(out, []byte("kind"))
	out = mpStr(out, []byte(kind))
	if len(fields) > 0 {
		out = mpStr(out, []byte(kind))
		out = mpMap(out, len(fields))
		for _, f := range fields {
			out = mpStr(out, []byte(f.key))
			switch f.kind {
			case auditStr:
				out = mpStr(out, f.data)
			case auditUint:
				out = mpUint(out, f.u64)
			case auditInt:
				out = mpInt(out, f.i64)
			case auditBool:
				if f.b {
					out = append(out, 0xc3)
				} else {
					out = append(out, 0xc2)
				}
			case auditBin:
				out = mpBin(out, f.data)
			}
		}
	}
	if len(out) > uapi.KACS_ACCESS_CHECK_MAX_AUDIT_CONTEXT_LEN {
		return nil, fmt.Errorf("libp/sd: audit context is %d bytes, over %d: %w",
			len(out), uapi.KACS_ACCESS_CHECK_MAX_AUDIT_CONTEXT_LEN, ErrBadAuditContext)
	}
	if err := ValidateAuditContext(out); err != nil {
		return nil, err
	}
	return out, nil
}

// ValidateAuditContext reports whether b is an audit context the kernel
// accepts, by the kernel's own rules: a map holding a segment-string
// kind and at most one other key, equal to the kind, whose value is a
// non-empty map with segment keys; well-formed MessagePack with UTF-8
// strings, nesting no deeper than the emit limit less one; at most
// KACS_ACCESS_CHECK_MAX_AUDIT_CONTEXT_LEN bytes. Check runs it on a
// non-empty CheckRequest.AuditContext before the syscall.
func ValidateAuditContext(b []byte) error {
	if len(b) == 0 || len(b) > uapi.KACS_ACCESS_CHECK_MAX_AUDIT_CONTEXT_LEN {
		return ErrBadAuditContext
	}
	if !auditContextShape(b) || !mpWellFormed(b, auditContextMaxDepth) {
		return ErrBadAuditContext
	}
	return nil
}

// isEventSegment is PGSS §6.3's segment grammar, [a-z][a-z0-9]*(-[a-z0-9]+)*.
func isEventSegment(s []byte) bool {
	if len(s) == 0 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	prev := s[0]
	for _, c := range s[1:] {
		ok := (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (c == '-' && prev != '-')
		if !ok {
			return false
		}
		prev = c
	}
	return prev != '-'
}

// ---- encoding ---------------------------------------------------------

func mpMap(out []byte, n int) []byte {
	if n <= 15 {
		return append(out, 0x80|byte(n))
	}
	if n <= math.MaxUint16 {
		return binary.BigEndian.AppendUint16(append(out, 0xde), uint16(n))
	}
	return binary.BigEndian.AppendUint32(append(out, 0xdf), uint32(n))
}

func mpStr(out, s []byte) []byte {
	n := len(s)
	switch {
	case n <= 31:
		out = append(out, 0xa0|byte(n))
	case n <= math.MaxUint8:
		out = append(out, 0xd9, byte(n))
	case n <= math.MaxUint16:
		out = binary.BigEndian.AppendUint16(append(out, 0xda), uint16(n))
	default:
		out = binary.BigEndian.AppendUint32(append(out, 0xdb), uint32(n))
	}
	return append(out, s...)
}

func mpBin(out, b []byte) []byte {
	n := len(b)
	switch {
	case n <= math.MaxUint8:
		out = append(out, 0xc4, byte(n))
	case n <= math.MaxUint16:
		out = binary.BigEndian.AppendUint16(append(out, 0xc5), uint16(n))
	default:
		out = binary.BigEndian.AppendUint32(append(out, 0xc6), uint32(n))
	}
	return append(out, b...)
}

func mpUint(out []byte, v uint64) []byte {
	switch {
	case v < 0x80:
		return append(out, byte(v))
	case v <= math.MaxUint8:
		return append(out, 0xcc, byte(v))
	case v <= math.MaxUint16:
		return binary.BigEndian.AppendUint16(append(out, 0xcd), uint16(v))
	case v <= math.MaxUint32:
		return binary.BigEndian.AppendUint32(append(out, 0xce), uint32(v))
	default:
		return binary.BigEndian.AppendUint64(append(out, 0xcf), v)
	}
}

func mpInt(out []byte, v int64) []byte {
	switch {
	case v >= 0:
		return mpUint(out, uint64(v))
	case v >= -32:
		return append(out, byte(v))
	case v >= math.MinInt8:
		return append(out, 0xd0, byte(v))
	case v >= math.MinInt16:
		return binary.BigEndian.AppendUint16(append(out, 0xd1), uint16(v))
	case v >= math.MinInt32:
		return binary.BigEndian.AppendUint32(append(out, 0xd2), uint32(v))
	default:
		return binary.BigEndian.AppendUint64(append(out, 0xd3), uint64(v))
	}
}

// ---- the kernel's structural reader -----------------------------------

type mpCursor struct {
	b   []byte
	pos int
}

func (c *mpCursor) take(n int) ([]byte, bool) {
	if n < 0 || n > len(c.b)-c.pos {
		return nil, false
	}
	out := c.b[c.pos : c.pos+n]
	c.pos += n
	return out, true
}

func (c *mpCursor) be(width int) (int, bool) {
	raw, ok := c.take(width)
	if !ok {
		return 0, false
	}
	var v uint64
	for _, x := range raw {
		v = v<<8 | uint64(x)
	}
	if v > math.MaxInt32 {
		return 0, false
	}
	return int(v), true
}

func (c *mpCursor) mapLen() (int, bool) {
	tag, ok := c.take(1)
	if !ok {
		return 0, false
	}
	switch t := tag[0]; {
	case t >= 0x80 && t <= 0x8f:
		return int(t & 0x0f), true
	case t == 0xde:
		return c.be(2)
	case t == 0xdf:
		return c.be(4)
	}
	return 0, false
}

func (c *mpCursor) str() ([]byte, bool) {
	tag, ok := c.take(1)
	if !ok {
		return nil, false
	}
	var n int
	switch t := tag[0]; {
	case t >= 0xa0 && t <= 0xbf:
		n = int(t & 0x1f)
	case t == 0xd9:
		n, ok = c.be(1)
	case t == 0xda:
		n, ok = c.be(2)
	case t == 0xdb:
		n, ok = c.be(4)
	default:
		return nil, false
	}
	if !ok {
		return nil, false
	}
	s, ok := c.take(n)
	if !ok || !utf8.Valid(s) {
		return nil, false
	}
	return s, true
}

// step consumes one value's header and payload, reporting how many child
// values follow it.
func (c *mpCursor) step() (children int, ok bool) {
	tag, ok := c.take(1)
	if !ok {
		return 0, false
	}
	t := tag[0]
	skip := 0
	switch {
	case t <= 0x7f || t >= 0xe0 || t == 0xc0 || t == 0xc2 || t == 0xc3:
	case t >= 0x80 && t <= 0x8f:
		children = int(t&0x0f) * 2
	case t >= 0x90 && t <= 0x9f:
		children = int(t & 0x0f)
	case t >= 0xa0 && t <= 0xbf:
		skip = int(t & 0x1f)
	case t == 0xc4 || t == 0xd9:
		skip, ok = c.be(1)
	case t == 0xc5 || t == 0xda:
		skip, ok = c.be(2)
	case t == 0xc6 || t == 0xdb:
		skip, ok = c.be(4)
	case t == 0xc7:
		skip, ok = c.be(1)
		skip++
	case t == 0xc8:
		skip, ok = c.be(2)
		skip++
	case t == 0xc9:
		skip, ok = c.be(4)
		skip++
	case t == 0xca:
		skip = 4
	case t == 0xcb:
		skip = 8
	case t == 0xcc || t == 0xd0:
		skip = 1
	case t == 0xcd || t == 0xd1:
		skip = 2
	case t == 0xce || t == 0xd2:
		skip = 4
	case t == 0xcf || t == 0xd3:
		skip = 8
	case t == 0xd4:
		skip = 2
	case t == 0xd5:
		skip = 3
	case t == 0xd6:
		skip = 5
	case t == 0xd7:
		skip = 9
	case t == 0xd8:
		skip = 17
	case t == 0xdc:
		children, ok = c.be(2)
	case t == 0xdd:
		children, ok = c.be(4)
	case t == 0xde:
		children, ok = c.be(2)
		children *= 2
	case t == 0xdf:
		children, ok = c.be(4)
		children *= 2
	default: // 0xc1, reserved
		return 0, false
	}
	if !ok {
		return 0, false
	}
	if t == 0xd9 || t == 0xda || t == 0xdb || (t >= 0xa0 && t <= 0xbf) {
		s, ok := c.take(skip)
		return 0, ok && utf8.Valid(s)
	}
	if _, ok := c.take(skip); !ok {
		return 0, false
	}
	// Every value takes at least one byte.
	if children > len(c.b)-c.pos {
		return 0, false
	}
	return children, true
}

// skipValue steps over one complete value.
func (c *mpCursor) skipValue() bool {
	pending := 1
	for pending > 0 {
		pending--
		children, ok := c.step()
		if !ok {
			return false
		}
		pending += children
		if pending > len(c.b)-c.pos {
			return false
		}
	}
	return true
}

// mpWellFormed is the kernel's emit-time check: one value consuming every
// byte, UTF-8 strings, and nesting bounded by maxDepth (the top level is
// depth 1; a non-empty container's children sit one level deeper).
func mpWellFormed(b []byte, maxDepth int) bool {
	c := mpCursor{b: b}
	stack := []int{1}
	for len(stack) > 0 {
		if stack[len(stack)-1] == 0 {
			stack = stack[:len(stack)-1]
			continue
		}
		stack[len(stack)-1]--
		children, ok := c.step()
		if !ok {
			return false
		}
		if children > 0 {
			if len(stack) >= maxDepth {
				return false
			}
			stack = append(stack, children)
		}
	}
	return c.pos == len(b)
}

// auditContextShape is the shape check of the kernel's
// parse_audit_context_map.
func auditContextShape(b []byte) bool {
	c := mpCursor{b: b}
	entries, ok := c.mapLen()
	if !ok || entries == 0 || entries > 2 {
		return false
	}
	var kind []byte
	var otherKey, otherValue []byte
	for range entries {
		key, ok := c.str()
		if !ok {
			return false
		}
		start := c.pos
		if !c.skipValue() {
			return false
		}
		value := b[start:c.pos]
		if string(key) == "kind" {
			if kind != nil {
				return false
			}
			vc := mpCursor{b: value}
			k, ok := vc.str()
			if !ok || vc.pos != len(value) || !isEventSegment(k) {
				return false
			}
			kind = k
		} else {
			otherKey, otherValue = key, value
		}
	}
	if c.pos != len(b) || kind == nil {
		return false
	}
	if otherKey == nil {
		return true
	}
	if string(otherKey) != string(kind) {
		return false
	}
	body := mpCursor{b: otherValue}
	n, ok := body.mapLen()
	if !ok || n == 0 {
		return false
	}
	for range n {
		k, ok := body.str()
		if !ok || !isEventSegment(k) {
			return false
		}
		if !body.skipValue() {
			return false
		}
	}
	return body.pos == len(otherValue)
}
