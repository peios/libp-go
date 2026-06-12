package registry

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf8"

	uapi "github.com/peios/pkm/uapi/go"
)

// Type is an LCS value-type code (a REG_* tag).
type Type uint32

// The registry value types (PSD-005 §2.5).
const (
	TypeNone           Type = uapi.REG_NONE
	TypeSZ             Type = uapi.REG_SZ
	TypeExpandSZ       Type = uapi.REG_EXPAND_SZ
	TypeBinary         Type = uapi.REG_BINARY
	TypeDWORD          Type = uapi.REG_DWORD
	TypeDWORDBigEndian Type = uapi.REG_DWORD_BIG_ENDIAN
	TypeLink           Type = uapi.REG_LINK
	TypeMultiSZ        Type = uapi.REG_MULTI_SZ
	TypeQWORD          Type = uapi.REG_QWORD
	// typeTombstone is the per-value tombstone marker; it is written
	// through LayerWrite.TombstoneValue, never constructed as a Value.
	typeTombstone Type = uapi.REG_TOMBSTONE
)

// String names the type, or its numeric form for an unrecognised tag.
func (t Type) String() string {
	switch t {
	case TypeNone:
		return "REG_NONE"
	case TypeSZ:
		return "REG_SZ"
	case TypeExpandSZ:
		return "REG_EXPAND_SZ"
	case TypeBinary:
		return "REG_BINARY"
	case TypeDWORD:
		return "REG_DWORD"
	case TypeDWORDBigEndian:
		return "REG_DWORD_BIG_ENDIAN"
	case TypeLink:
		return "REG_LINK"
	case TypeMultiSZ:
		return "REG_MULTI_SZ"
	case TypeQWORD:
		return "REG_QWORD"
	default:
		return fmt.Sprintf("REG_type(%d)", uint32(t))
	}
}

// Value is a typed registry value. Construct one with a typed constructor
// (SZ, DWORD, …) and read it back with the matching accessor (Str,
// Uint32, …). The zero Value is a REG_NONE.
//
// Decoding from the kernel never fails on an *unknown* type tag — it
// preserves the tag and bytes (see Other) so values always round-trip. It
// fails only when a known fixed-width or string type holds bytes that
// don't fit that type (a short DWORD, non-UTF-8 SZ): see ErrMalformedValue.
type Value struct {
	typ  Type
	s    string   // SZ / EXPAND_SZ / LINK
	list []string // MULTI_SZ
	num  uint64   // DWORD / DWORD_BIG_ENDIAN / QWORD
	b    []byte   // BINARY / Other
}

// None returns a typed-but-empty REG_NONE value.
func None() Value { return Value{typ: TypeNone} }

// SZ returns a REG_SZ string value.
func SZ(s string) Value { return Value{typ: TypeSZ, s: s} }

// ExpandSZ returns a REG_EXPAND_SZ value — a string with %VAR%-style
// references the registry stores uninterpreted.
func ExpandSZ(s string) Value { return Value{typ: TypeExpandSZ, s: s} }

// Link returns a REG_LINK symlink-target value.
func Link(s string) Value { return Value{typ: TypeLink, s: s} }

// MultiSZ returns a REG_MULTI_SZ ordered list of strings.
func MultiSZ(list []string) Value { return Value{typ: TypeMultiSZ, list: list} }

// Binary returns a REG_BINARY raw-bytes value.
func Binary(b []byte) Value { return Value{typ: TypeBinary, b: b} }

// DWORD returns a REG_DWORD 32-bit value (stored little-endian).
func DWORD(n uint32) Value { return Value{typ: TypeDWORD, num: uint64(n)} }

// DWORDBigEndian returns a REG_DWORD_BIG_ENDIAN 32-bit value (stored
// big-endian).
func DWORDBigEndian(n uint32) Value { return Value{typ: TypeDWORDBigEndian, num: uint64(n)} }

// QWORD returns a REG_QWORD 64-bit value (stored little-endian).
func QWORD(n uint64) Value { return Value{typ: TypeQWORD, num: n} }

// Other returns a value of an arbitrary type tag carrying opaque bytes —
// for hardware-resource types (8–10) or a tag a future kernel adds, so
// the value round-trips verbatim. Use the typed constructors for the
// known types.
func Other(t Type, data []byte) Value { return Value{typ: t, b: data} }

// Kind reports the value's REG_* type code.
func (v Value) Kind() Type { return v.typ }

// Str returns the string and true if this is a string type (SZ /
// EXPAND_SZ / LINK), else "" and false.
func (v Value) Str() (string, bool) {
	switch v.typ {
	case TypeSZ, TypeExpandSZ, TypeLink:
		return v.s, true
	default:
		return "", false
	}
}

// Uint32 returns the value and true if this is a DWORD (either
// endianness), else 0 and false.
func (v Value) Uint32() (uint32, bool) {
	switch v.typ {
	case TypeDWORD, TypeDWORDBigEndian:
		return uint32(v.num), true
	default:
		return 0, false
	}
}

// Uint64 returns the value and true if this is a QWORD, else 0 and false.
func (v Value) Uint64() (uint64, bool) {
	if v.typ == TypeQWORD {
		return v.num, true
	}
	return 0, false
}

// List returns the strings and true if this is a MULTI_SZ, else nil and
// false.
func (v Value) List() ([]string, bool) {
	if v.typ == TypeMultiSZ {
		return v.list, true
	}
	return nil, false
}

// Bytes returns the raw bytes and true if this is BINARY or an Other /
// opaque type, else nil and false.
func (v Value) Bytes() ([]byte, bool) {
	switch v.typ {
	case TypeBinary:
		return v.b, true
	default:
		if isKnown(v.typ) {
			return nil, false
		}
		return v.b, true
	}
}

// Encode returns the on-the-wire (type code, data bytes) pair the kernel
// stores.
func (v Value) Encode() (Type, []byte) {
	switch v.typ {
	case TypeNone:
		return TypeNone, nil
	case TypeSZ, TypeExpandSZ, TypeLink:
		return v.typ, encodeSZ(v.s)
	case TypeBinary:
		return TypeBinary, v.b
	case TypeDWORD:
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, uint32(v.num))
		return TypeDWORD, b
	case TypeDWORDBigEndian:
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, uint32(v.num))
		return TypeDWORDBigEndian, b
	case TypeMultiSZ:
		return TypeMultiSZ, encodeMultiSZ(v.list)
	case TypeQWORD:
		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, v.num)
		return TypeQWORD, b
	default:
		return v.typ, v.b
	}
}

// Decode decodes a (type code, data bytes) pair returned by the kernel.
// An unknown type tag is preserved verbatim via Other and never errors; a
// malformed known type yields ErrMalformedValue.
func Decode(t Type, data []byte) (Value, error) {
	switch t {
	case TypeNone:
		return None(), nil
	case TypeSZ:
		s, err := decodeSZ(data, t)
		return Value{typ: t, s: s}, err
	case TypeExpandSZ:
		s, err := decodeSZ(data, t)
		return Value{typ: t, s: s}, err
	case TypeLink:
		s, err := decodeSZ(data, t)
		return Value{typ: t, s: s}, err
	case TypeBinary:
		return Binary(append([]byte(nil), data...)), nil
	case TypeDWORD:
		if len(data) != 4 {
			return Value{}, malformed(t, "want 4 bytes, got %d", len(data))
		}
		return DWORD(binary.LittleEndian.Uint32(data)), nil
	case TypeDWORDBigEndian:
		if len(data) != 4 {
			return Value{}, malformed(t, "want 4 bytes, got %d", len(data))
		}
		return DWORDBigEndian(binary.BigEndian.Uint32(data)), nil
	case TypeMultiSZ:
		list, err := decodeMultiSZ(data)
		return Value{typ: t, list: list}, err
	case TypeQWORD:
		if len(data) != 8 {
			return Value{}, malformed(t, "want 8 bytes, got %d", len(data))
		}
		return QWORD(binary.LittleEndian.Uint64(data)), nil
	default:
		return Other(t, append([]byte(nil), data...)), nil
	}
}

// isKnown reports whether t is one of the types Value models with a
// dedicated field (so an Other value carries a distinct tag).
func isKnown(t Type) bool {
	switch t {
	case TypeNone, TypeSZ, TypeExpandSZ, TypeLink, TypeBinary,
		TypeDWORD, TypeDWORDBigEndian, TypeMultiSZ, TypeQWORD:
		return true
	default:
		return false
	}
}

// encodeSZ encodes a string as UTF-8 with a trailing NUL.
func encodeSZ(s string) []byte {
	b := make([]byte, 0, len(s)+1)
	b = append(b, s...)
	return append(b, 0)
}

// encodeMultiSZ encodes each string as UTF-8 + NUL, with a final NUL.
func encodeMultiSZ(list []string) []byte {
	var b []byte
	for _, s := range list {
		b = append(b, s...)
		b = append(b, 0)
	}
	return append(b, 0)
}

// decodeSZ strips one trailing NUL (if present) and validates UTF-8.
func decodeSZ(data []byte, t Type) (string, error) {
	if n := len(data); n > 0 && data[n-1] == 0 {
		data = data[:n-1]
	}
	if !utf8.Valid(data) {
		return "", malformed(t, "data is not valid UTF-8")
	}
	return string(data), nil
}

// decodeMultiSZ splits on NUL, dropping empty segments (the trailing
// terminator and the final list NUL), and validates each is UTF-8.
func decodeMultiSZ(data []byte) ([]string, error) {
	var out []string
	for _, seg := range splitNUL(data) {
		if len(seg) == 0 {
			continue
		}
		if !utf8.Valid(seg) {
			return nil, malformed(TypeMultiSZ, "a string is not valid UTF-8")
		}
		out = append(out, string(seg))
	}
	return out, nil
}

// splitNUL splits b on NUL bytes (like bytes.Split, but without importing
// the package for one call).
func splitNUL(b []byte) [][]byte {
	var out [][]byte
	start := 0
	for i, c := range b {
		if c == 0 {
			out = append(out, b[start:i])
			start = i + 1
		}
	}
	out = append(out, b[start:])
	return out
}

// malformed builds an ErrMalformedValue with the offending type and a
// detail message.
func malformed(t Type, format string, args ...any) error {
	return fmt.Errorf("libp/registry: malformed %s value: %s: %w",
		t, fmt.Sprintf(format, args...), ErrMalformedValue)
}

// String renders the value for debugging — type plus a compact form of
// the payload. It is not the value's stored string; use Str for that.
func (v Value) String() string {
	switch v.typ {
	case TypeSZ, TypeExpandSZ, TypeLink:
		return fmt.Sprintf("%s(%q)", v.typ, v.s)
	case TypeDWORD, TypeDWORDBigEndian:
		return fmt.Sprintf("%s(%d)", v.typ, uint32(v.num))
	case TypeQWORD:
		return fmt.Sprintf("%s(%d)", v.typ, v.num)
	case TypeMultiSZ:
		return fmt.Sprintf("%s[%s]", v.typ, strings.Join(v.list, ","))
	case TypeNone:
		return "REG_NONE"
	default:
		return fmt.Sprintf("%s(%d bytes)", v.typ, len(v.b))
	}
}
