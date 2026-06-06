package sd

import (
	"encoding/binary"
	"unicode/utf16"

	"github.com/peios/libp-go/wire"
)

// Conditional-ACE bytecode tokens (PSD-004 §3.11) — a postfix token
// stream, all multibyte integers little-endian. These are a userspace
// wire format with no kernel UAPI header, so the values are inline.
const (
	tokInt64        = 0x04
	tokString       = 0x10
	tokOctet        = 0x18
	tokComposite    = 0x50
	tokSID          = 0x51
	tokExists       = 0x87
	tokNotExists    = 0x8d
	tokAnd          = 0xa0
	tokOr           = 0xa1
	tokNot          = 0xa2
	tokAttrLocal    = 0xf8
	tokAttrUser     = 0xf9
	tokAttrResource = 0xfa
	tokAttrDevice   = 0xfb

	signNegative = 0x02
	signNone     = 0x03
	baseDecimal  = 0x02
)

// CompareOp is a binary relational operator in a conditional expression.
// Its value is the operator's bytecode token.
type CompareOp uint8

const (
	OpEqual        CompareOp = 0x80
	OpNotEqual     CompareOp = 0x81
	OpLess         CompareOp = 0x82
	OpLessEqual    CompareOp = 0x83
	OpGreater      CompareOp = 0x84
	OpGreaterEqual CompareOp = 0x85
	OpContains     CompareOp = 0x86
	OpAnyOf        CompareOp = 0x88
	OpNotContains  CompareOp = 0x8e
	OpNotAnyOf     CompareOp = 0x8f
)

// MemberOp is a SID-membership operator. The implicit subject is the
// caller's token; the operand is a SID or a composite of SIDs.
type MemberOp uint8

const (
	OpMemberOf             MemberOp = 0x89
	OpDeviceMemberOf       MemberOp = 0x8a
	OpMemberOfAny          MemberOp = 0x8b
	OpDeviceMemberOfAny    MemberOp = 0x8c
	OpNotMemberOf          MemberOp = 0x90
	OpNotDeviceMemberOf    MemberOp = 0x91
	OpNotMemberOfAny       MemberOp = 0x92
	OpNotDeviceMemberOfAny MemberOp = 0x93
)

// Operand is one operand of a conditional-ACE expression — a literal, an
// attribute reference, or a composite. Build one with the constructor
// functions below.
//
// Operand and Condition are build-only: they hold the encoded postfix
// fragment, composed by the constructors. There is no traversable AST —
// a conditional expression is built and encoded, never inspected.
type Operand struct {
	tok []byte
}

// IntOperand is a signed 64-bit integer literal.
func IntOperand(n int64) Operand {
	b := []byte{tokInt64}
	b = binary.LittleEndian.AppendUint64(b, uint64(n))
	if n < 0 {
		b = append(b, signNegative)
	} else {
		b = append(b, signNone)
	}
	return Operand{append(b, baseDecimal)}
}

// StringOperand is a Unicode string literal.
func StringOperand(s string) Operand { return Operand{tokenWith(tokString, utf16le(s))} }

// SIDOperand is a SID literal.
func SIDOperand(sid wire.SID) Operand { return Operand{tokenWith(tokSID, sid.Bytes())} }

// OctetOperand is an octet-string literal.
func OctetOperand(data []byte) Operand { return Operand{tokenWith(tokOctet, data)} }

// LocalAttr references an @Local.<name> claim passed to AccessCheck.
func LocalAttr(name string) Operand { return Operand{tokenWith(tokAttrLocal, utf16le(name))} }

// UserAttr references an @User.<name> claim from the caller's token.
func UserAttr(name string) Operand { return Operand{tokenWith(tokAttrUser, utf16le(name))} }

// ResourceAttr references an @Resource.<name> attribute from the object.
func ResourceAttr(name string) Operand { return Operand{tokenWith(tokAttrResource, utf16le(name))} }

// DeviceAttr references an @Device.<name> claim from the caller's token.
func DeviceAttr(name string) Operand { return Operand{tokenWith(tokAttrDevice, utf16le(name))} }

// Composite groups operands — typically a set of SIDs for a membership
// operator.
func Composite(items ...Operand) Operand {
	var inner []byte
	for _, it := range items {
		inner = append(inner, it.tok...)
	}
	return Operand{tokenWith(tokComposite, inner)}
}

// tokenWith builds a token: a tag byte, a u32 little-endian length, data.
func tokenWith(tag byte, data []byte) []byte {
	b := []byte{tag}
	b = binary.LittleEndian.AppendUint32(b, uint32(len(data)))
	return append(b, data...)
}

// Condition is a conditional-ACE expression. Build leaves with Compare /
// Member / Exists / NotExists, combine with And / Or / Not, and encode
// into a callback ACE with the AllowCallback family.
type Condition struct {
	tok []byte
}

// Compare relates two operands.
func Compare(op CompareOp, lhs, rhs Operand) Condition {
	b := append([]byte(nil), lhs.tok...)
	b = append(b, rhs.tok...)
	return Condition{append(b, byte(op))}
}

// Member tests SID membership of the caller's token against operand.
func Member(op MemberOp, operand Operand) Condition {
	b := append([]byte(nil), operand.tok...)
	return Condition{append(b, byte(op))}
}

// Exists is true when operand is a present, non-null attribute.
func Exists(operand Operand) Condition {
	return Condition{append(append([]byte(nil), operand.tok...), tokExists)}
}

// NotExists is the negation of Exists.
func NotExists(operand Operand) Condition {
	return Condition{append(append([]byte(nil), operand.tok...), tokNotExists)}
}

// And combines two conditions under logical conjunction.
func (c Condition) And(rhs Condition) Condition {
	b := append([]byte(nil), c.tok...)
	b = append(b, rhs.tok...)
	return Condition{append(b, tokAnd)}
}

// Or combines two conditions under logical disjunction.
func (c Condition) Or(rhs Condition) Condition {
	b := append([]byte(nil), c.tok...)
	b = append(b, rhs.tok...)
	return Condition{append(b, tokOr)}
}

// Not logically negates the condition.
func (c Condition) Not() Condition {
	return Condition{append(append([]byte(nil), c.tok...), tokNot)}
}

// Encode emits the artx-prefixed conditional-ACE bytecode: the magic,
// the expression's tokens in postfix order, then 0x00 padding to a
// 4-byte boundary. This is the ApplicationData body of a callback ACE.
func (c Condition) Encode() []byte {
	out := append([]byte("artx"), c.tok...)
	for len(out)%4 != 0 {
		out = append(out, 0)
	}
	return out
}

// utf16le encodes s as UTF-16LE bytes with no NUL terminator.
func utf16le(s string) []byte {
	units := utf16.Encode([]rune(s))
	b := make([]byte, 0, len(units)*2)
	for _, u := range units {
		b = append(b, byte(u), byte(u>>8))
	}
	return b
}
