package sddl

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/peios/libp-go/sd"
	"github.com/peios/libp-go/wire"
)

// This file decodes the artx callback-ACE bytecode back into SDDL
// conditional-expression text — the reverse of condition.go.

// artx conditional-expression token tags. These mirror the frozen
// userspace wire format that sd's Condition builders emit (PSD-004
// §3.11); sd keeps the literal and logical tags unexported, so they are
// repeated here for the decoder. The relational and membership
// operator bytes are sd.CompareOp / sd.MemberOp values and are matched
// directly against those exported constants.
const (
	artxMagic = "artx"

	tkInt64     = 0x04
	tkString    = 0x10
	tkOctet     = 0x18
	tkComposite = 0x50
	tkSID       = 0x51
	tkExists    = 0x87
	tkNotExists = 0x8d
	tkAnd       = 0xa0
	tkOr        = 0xa1
	tkNot       = 0xa2
	tkAttrLocal = 0xf8
	tkAttrUser  = 0xf9
	tkAttrRes   = 0xfa
	tkAttrDev   = 0xfb
)

var (
	errTrunc     = errors.New("truncated conditional expression")
	errUnderflow = errors.New("malformed conditional expression: operand stack underflow")
)

// compareSym and memberKw render an operator byte back to its text.
var compareSym = map[sd.CompareOp]string{
	sd.OpEqual: "==", sd.OpNotEqual: "!=",
	sd.OpLess: "<", sd.OpLessEqual: "<=",
	sd.OpGreater: ">", sd.OpGreaterEqual: ">=",
	sd.OpContains: "Contains", sd.OpAnyOf: "Any_of",
	sd.OpNotContains: "Not_Contains", sd.OpNotAnyOf: "Not_Any_of",
}

var memberKw = map[sd.MemberOp]string{
	sd.OpMemberOf:             "Member_of",
	sd.OpDeviceMemberOf:       "Device_Member_of",
	sd.OpMemberOfAny:          "Member_of_Any",
	sd.OpDeviceMemberOfAny:    "Device_Member_of_Any",
	sd.OpNotMemberOf:          "Not_Member_of",
	sd.OpNotDeviceMemberOf:    "Not_Device_Member_of",
	sd.OpNotMemberOfAny:       "Not_Member_of_Any",
	sd.OpNotDeviceMemberOfAny: "Not_Device_Member_of_Any",
}

// decodeCondition renders an artx-encoded conditional expression — the
// callback-ACE body tail after the mask, object header and SID — as
// SDDL conditional-expression text, with no surrounding parentheses.
func decodeCondition(code []byte, opt options) (string, error) {
	if len(code) < 4 || string(code[:4]) != artxMagic {
		return "", fmt.Errorf("conditional expression is missing the %q prefix", artxMagic)
	}
	stack, err := decodeTokens(code[4:], opt)
	if err != nil {
		return "", err
	}
	if len(stack) != 1 {
		return "", fmt.Errorf("conditional expression left %d values on the stack, want 1", len(stack))
	}
	return stack[0], nil
}

// decodeTokens walks a postfix token stream — stopping at the first
// 0x00 padding byte — and returns the resulting operand/condition
// stack. For a whole expression the stack holds one value; for a
// composite's inner data it holds the composite's items.
func decodeTokens(b []byte, opt options) ([]string, error) {
	var stack []string
	pop := func() (string, bool) {
		if len(stack) == 0 {
			return "", false
		}
		v := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		return v, true
	}

	for i := 0; i < len(b); {
		tag := b[i]
		switch tag {
		case 0x00:
			return stack, nil // padding — the stream is done

		case tkInt64:
			if i+11 > len(b) {
				return nil, errTrunc
			}
			v := int64(binary.LittleEndian.Uint64(b[i+1 : i+9]))
			stack = append(stack, strconv.FormatInt(v, 10))
			i += 11

		case tkString, tkOctet, tkSID, tkComposite,
			tkAttrLocal, tkAttrUser, tkAttrRes, tkAttrDev:
			if i+5 > len(b) {
				return nil, errTrunc
			}
			n := int(binary.LittleEndian.Uint32(b[i+1 : i+5]))
			if n < 0 || i+5+n > len(b) {
				return nil, errTrunc
			}
			s, err := decodeDataToken(tag, b[i+5:i+5+n], opt)
			if err != nil {
				return nil, err
			}
			stack = append(stack, s)
			i += 5 + n

		case tkExists, tkNotExists:
			operand, ok := pop()
			if !ok {
				return nil, errUnderflow
			}
			kw := "Exists"
			if tag == tkNotExists {
				kw = "Not_Exists"
			}
			stack = append(stack, kw+" "+operand)
			i++

		case tkNot:
			sub, ok := pop()
			if !ok {
				return nil, errUnderflow
			}
			stack = append(stack, "!("+sub+")")
			i++

		case tkAnd, tkOr:
			rhs, ok1 := pop()
			lhs, ok2 := pop()
			if !ok1 || !ok2 {
				return nil, errUnderflow
			}
			sym := "&&"
			if tag == tkOr {
				sym = "||"
			}
			stack = append(stack, "("+lhs+") "+sym+" ("+rhs+")")
			i++

		default:
			if sym, ok := compareSym[sd.CompareOp(tag)]; ok {
				rhs, ok1 := pop()
				lhs, ok2 := pop()
				if !ok1 || !ok2 {
					return nil, errUnderflow
				}
				stack = append(stack, lhs+" "+sym+" "+rhs)
				i++
			} else if kw, ok := memberKw[sd.MemberOp(tag)]; ok {
				operand, ok := pop()
				if !ok {
					return nil, errUnderflow
				}
				stack = append(stack, kw+" "+operand)
				i++
			} else {
				return nil, fmt.Errorf("unknown conditional token 0x%02x", tag)
			}
		}
	}
	return stack, nil
}

// decodeDataToken renders a length-prefixed operand token.
func decodeDataToken(tag byte, data []byte, opt options) (string, error) {
	switch tag {
	case tkString:
		return `"` + utf16Decode(data) + `"`, nil
	case tkOctet:
		return "#" + hex.EncodeToString(data), nil
	case tkSID:
		sid, err := wire.ParseSID(data)
		if err != nil {
			return "", fmt.Errorf("malformed SID literal: %w", err)
		}
		return "SID(" + opt.formatSID(sid) + ")", nil
	case tkComposite:
		items, err := decodeTokens(data, opt)
		if err != nil {
			return "", err
		}
		return "{" + strings.Join(items, ", ") + "}", nil
	case tkAttrLocal:
		return utf16Decode(data), nil
	case tkAttrUser:
		return "@User." + utf16Decode(data), nil
	case tkAttrRes:
		return "@Resource." + utf16Decode(data), nil
	case tkAttrDev:
		return "@Device." + utf16Decode(data), nil
	default:
		return "", fmt.Errorf("unknown data token 0x%02x", tag)
	}
}

// utf16Decode decodes UTF-16LE bytes to a string.
func utf16Decode(b []byte) string {
	units := make([]uint16, len(b)/2)
	for i := range units {
		units[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
	}
	return string(utf16.Decode(units))
}
