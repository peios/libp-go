package sddl

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/peios/libp-go/sd"
)

// This file compiles the SDDL conditional-expression text (MS-DTYP
// §2.5.1.2) into an sd.Condition, whose Encode method emits the artx
// callback-ACE bytecode. The reverse — bytecode back to text — is in
// decompile.go.

// --- relational and membership operator vocabulary ------------------

var relSymbols = map[string]sd.CompareOp{
	"==": sd.OpEqual, "!=": sd.OpNotEqual,
	"<": sd.OpLess, "<=": sd.OpLessEqual,
	">": sd.OpGreater, ">=": sd.OpGreaterEqual,
}

var relKeywords = map[string]sd.CompareOp{
	"Contains": sd.OpContains, "Any_of": sd.OpAnyOf,
	"Not_Contains": sd.OpNotContains, "Not_Any_of": sd.OpNotAnyOf,
}

var memberOps = map[string]sd.MemberOp{
	"Member_of":                sd.OpMemberOf,
	"Device_Member_of":         sd.OpDeviceMemberOf,
	"Member_of_Any":            sd.OpMemberOfAny,
	"Device_Member_of_Any":     sd.OpDeviceMemberOfAny,
	"Not_Member_of":            sd.OpNotMemberOf,
	"Not_Device_Member_of":     sd.OpNotDeviceMemberOf,
	"Not_Member_of_Any":        sd.OpNotMemberOfAny,
	"Not_Device_Member_of_Any": sd.OpNotDeviceMemberOfAny,
}

// --- lexer -----------------------------------------------------------

type ctokKind uint8

const (
	ctEOF ctokKind = iota
	ctLParen
	ctRParen
	ctLBrace
	ctRBrace
	ctComma
	ctAndAnd
	ctOrOr
	ctBang
	ctRel   // a relational symbol: == != < <= > >=
	ctIdent // a bare identifier — an operator keyword or a Local attribute
	ctAttr  // an @Class.name attribute reference
	ctInt
	ctString
	ctSID
	ctOctet
)

type ctok struct {
	kind ctokKind
	pos  int
	text string
}

func isIdentStart(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_'
}

func isIdentChar(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9')
}

func isNumChar(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
		(c >= 'A' && c <= 'F') || c == 'x' || c == 'X'
}

// lexCondition tokenises an SDDL conditional expression.
func lexCondition(in string) ([]ctok, error) {
	var toks []ctok
	for i := 0; i < len(in); {
		c := in[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '(':
			toks = append(toks, ctok{ctLParen, i, "("})
			i++
		case c == ')':
			toks = append(toks, ctok{ctRParen, i, ")"})
			i++
		case c == '{':
			toks = append(toks, ctok{ctLBrace, i, "{"})
			i++
		case c == '}':
			toks = append(toks, ctok{ctRBrace, i, "}"})
			i++
		case c == ',':
			toks = append(toks, ctok{ctComma, i, ","})
			i++
		case c == '&':
			if i+1 >= len(in) || in[i+1] != '&' {
				return nil, fmt.Errorf("offset %d: expected '&&'", i)
			}
			toks = append(toks, ctok{ctAndAnd, i, "&&"})
			i += 2
		case c == '|':
			if i+1 >= len(in) || in[i+1] != '|' {
				return nil, fmt.Errorf("offset %d: expected '||'", i)
			}
			toks = append(toks, ctok{ctOrOr, i, "||"})
			i += 2
		case c == '!':
			if i+1 < len(in) && in[i+1] == '=' {
				toks = append(toks, ctok{ctRel, i, "!="})
				i += 2
			} else {
				toks = append(toks, ctok{ctBang, i, "!"})
				i++
			}
		case c == '=':
			if i+1 >= len(in) || in[i+1] != '=' {
				return nil, fmt.Errorf("offset %d: expected '=='", i)
			}
			toks = append(toks, ctok{ctRel, i, "=="})
			i += 2
		case c == '<' || c == '>':
			if i+1 < len(in) && in[i+1] == '=' {
				toks = append(toks, ctok{ctRel, i, in[i : i+2]})
				i += 2
			} else {
				toks = append(toks, ctok{ctRel, i, in[i : i+1]})
				i++
			}
		case c == '"':
			j := i + 1
			for j < len(in) && in[j] != '"' {
				j++
			}
			if j >= len(in) {
				return nil, fmt.Errorf("offset %d: unterminated string literal", i)
			}
			toks = append(toks, ctok{ctString, i, in[i+1 : j]})
			i = j + 1
		case c == '#':
			j := i + 1
			for j < len(in) && isHexDigit(in[j]) {
				j++
			}
			toks = append(toks, ctok{ctOctet, i, in[i+1 : j]})
			i = j
		case c == '@':
			j := i + 1
			for j < len(in) && (isIdentChar(in[j]) || in[j] == '.') {
				j++
			}
			toks = append(toks, ctok{ctAttr, i, in[i:j]})
			i = j
		case c == '-' || (c >= '0' && c <= '9'):
			j := i + 1
			for j < len(in) && isNumChar(in[j]) {
				j++
			}
			toks = append(toks, ctok{ctInt, i, in[i:j]})
			i = j
		case isIdentStart(c):
			j := i
			for j < len(in) && isIdentChar(in[j]) {
				j++
			}
			word := in[i:j]
			if word == "SID" && j < len(in) && in[j] == '(' {
				k := j + 1
				for k < len(in) && in[k] != ')' {
					k++
				}
				if k >= len(in) {
					return nil, fmt.Errorf("offset %d: unterminated SID(...)", i)
				}
				toks = append(toks, ctok{ctSID, i, in[j+1 : k]})
				i = k + 1
			} else {
				toks = append(toks, ctok{ctIdent, i, word})
				i = j
			}
		default:
			return nil, fmt.Errorf("offset %d: unexpected character %q", i, string(c))
		}
	}
	return append(toks, ctok{ctEOF, len(in), ""}), nil
}

// --- parser ----------------------------------------------------------

type condParser struct {
	toks []ctok
	pos  int
	opt  options
}

func (cp *condParser) peek() ctok { return cp.toks[cp.pos] }

func (cp *condParser) next() ctok {
	t := cp.toks[cp.pos]
	if cp.pos < len(cp.toks)-1 {
		cp.pos++
	}
	return t
}

// parseConditionText compiles a conditional-expression string into an
// sd.Condition. The string is the SDDL ACE conditional field, which is
// itself parenthesised — e.g. (@User.Title == "PM").
func parseConditionText(s string, opt options) (sd.Condition, error) {
	toks, err := lexCondition(s)
	if err != nil {
		return sd.Condition{}, err
	}
	cp := &condParser{toks: toks, opt: opt}
	cond, err := cp.parseExpr()
	if err != nil {
		return sd.Condition{}, err
	}
	if cp.peek().kind != ctEOF {
		return sd.Condition{}, fmt.Errorf("offset %d: unexpected %q after expression",
			cp.peek().pos, cp.peek().text)
	}
	return cond, nil
}

func (cp *condParser) parseExpr() (sd.Condition, error) { return cp.parseOr() }

func (cp *condParser) parseOr() (sd.Condition, error) {
	lhs, err := cp.parseAnd()
	if err != nil {
		return sd.Condition{}, err
	}
	for cp.peek().kind == ctOrOr {
		cp.next()
		rhs, err := cp.parseAnd()
		if err != nil {
			return sd.Condition{}, err
		}
		lhs = lhs.Or(rhs)
	}
	return lhs, nil
}

func (cp *condParser) parseAnd() (sd.Condition, error) {
	lhs, err := cp.parseUnary()
	if err != nil {
		return sd.Condition{}, err
	}
	for cp.peek().kind == ctAndAnd {
		cp.next()
		rhs, err := cp.parseUnary()
		if err != nil {
			return sd.Condition{}, err
		}
		lhs = lhs.And(rhs)
	}
	return lhs, nil
}

func (cp *condParser) parseUnary() (sd.Condition, error) {
	if cp.peek().kind == ctBang {
		cp.next()
		sub, err := cp.parseUnary()
		if err != nil {
			return sd.Condition{}, err
		}
		return sub.Not(), nil
	}
	return cp.parseTerm()
}

func (cp *condParser) parseTerm() (sd.Condition, error) {
	t := cp.peek()
	switch t.kind {
	case ctLParen:
		cp.next()
		e, err := cp.parseExpr()
		if err != nil {
			return sd.Condition{}, err
		}
		if cp.peek().kind != ctRParen {
			return sd.Condition{}, fmt.Errorf("offset %d: expected ')'", cp.peek().pos)
		}
		cp.next()
		return e, nil
	case ctIdent:
		// Exists, Not_Exists and the membership operators are prefix forms.
		if t.text == "Exists" || t.text == "Not_Exists" {
			cp.next()
			operand, err := cp.parseOperand()
			if err != nil {
				return sd.Condition{}, err
			}
			if t.text == "Exists" {
				return sd.Exists(operand), nil
			}
			return sd.NotExists(operand), nil
		}
		if mop, ok := memberOps[t.text]; ok {
			cp.next()
			operand, err := cp.parseOperand()
			if err != nil {
				return sd.Condition{}, err
			}
			return sd.Member(mop, operand), nil
		}
	}
	// Otherwise the term is an infix relation: operand op operand.
	lhs, err := cp.parseOperand()
	if err != nil {
		return sd.Condition{}, err
	}
	op, err := cp.parseRelOp()
	if err != nil {
		return sd.Condition{}, err
	}
	rhs, err := cp.parseOperand()
	if err != nil {
		return sd.Condition{}, err
	}
	return sd.Compare(op, lhs, rhs), nil
}

func (cp *condParser) parseRelOp() (sd.CompareOp, error) {
	t := cp.next()
	switch t.kind {
	case ctRel:
		op, ok := relSymbols[t.text]
		if !ok {
			return 0, fmt.Errorf("offset %d: unknown operator %q", t.pos, t.text)
		}
		return op, nil
	case ctIdent:
		op, ok := relKeywords[t.text]
		if !ok {
			return 0, fmt.Errorf("offset %d: expected a relational operator, got %q", t.pos, t.text)
		}
		return op, nil
	default:
		return 0, fmt.Errorf("offset %d: expected a relational operator", t.pos)
	}
}

func (cp *condParser) parseOperand() (sd.Operand, error) {
	t := cp.peek()
	switch t.kind {
	case ctInt:
		cp.next()
		n, err := strconv.ParseInt(t.text, 0, 64)
		if err != nil {
			return sd.Operand{}, fmt.Errorf("offset %d: malformed integer %q", t.pos, t.text)
		}
		return sd.IntOperand(n), nil
	case ctString:
		cp.next()
		return sd.StringOperand(t.text), nil
	case ctOctet:
		cp.next()
		raw, err := hex.DecodeString(t.text)
		if err != nil {
			return sd.Operand{}, fmt.Errorf("offset %d: malformed octet string", t.pos)
		}
		return sd.OctetOperand(raw), nil
	case ctSID:
		cp.next()
		sid, err := cp.opt.parseSIDText(t.text)
		if err != nil {
			return sd.Operand{}, fmt.Errorf("offset %d: %s", t.pos, err)
		}
		return sd.SIDOperand(sid), nil
	case ctAttr:
		cp.next()
		return attrOperand(t.text, t.pos)
	case ctIdent:
		// A bare identifier as an operand is a Local attribute.
		cp.next()
		return sd.LocalAttr(t.text), nil
	case ctLBrace:
		return cp.parseComposite()
	default:
		return sd.Operand{}, fmt.Errorf("offset %d: expected an operand", t.pos)
	}
}

// attrOperand builds an @Class.name attribute operand.
func attrOperand(text string, pos int) (sd.Operand, error) {
	dot := strings.IndexByte(text, '.')
	if dot < 0 {
		return sd.Operand{}, fmt.Errorf("offset %d: attribute %q needs a Class.name form", pos, text)
	}
	class, name := text[1:dot], text[dot+1:]
	if name == "" {
		return sd.Operand{}, fmt.Errorf("offset %d: attribute %q has an empty name", pos, text)
	}
	switch class {
	case "User":
		return sd.UserAttr(name), nil
	case "Device":
		return sd.DeviceAttr(name), nil
	case "Resource":
		return sd.ResourceAttr(name), nil
	default:
		return sd.Operand{}, fmt.Errorf("offset %d: unknown attribute class %q", pos, class)
	}
}

func (cp *condParser) parseComposite() (sd.Operand, error) {
	cp.next() // '{'
	var items []sd.Operand
	for cp.peek().kind != ctRBrace {
		if cp.peek().kind == ctEOF {
			return sd.Operand{}, fmt.Errorf("offset %d: unterminated '{'", cp.peek().pos)
		}
		item, err := cp.parseOperand()
		if err != nil {
			return sd.Operand{}, err
		}
		items = append(items, item)
		if cp.peek().kind == ctComma {
			cp.next()
		} else if cp.peek().kind != ctRBrace {
			return sd.Operand{}, fmt.Errorf("offset %d: expected ',' or '}'", cp.peek().pos)
		}
	}
	cp.next() // '}'
	return sd.Composite(items...), nil
}
