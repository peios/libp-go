package sd

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/peios/libp-go/wire"
	uapi "github.com/peios/pkm/uapi/go"
)

// ErrBadClaim reports a claim attribute that cannot be encoded.
var ErrBadClaim = errors.New("libp/sd: malformed claim attribute")

// claimKind is the variant tag of a ClaimValue.
type claimKind uint8

const (
	kindInt64 claimKind = iota
	kindUInt64
	kindBoolean
	kindString
	kindSID
	kindOctet
)

// typeCode maps a claimKind to its KACS_CLAIM_TYPE_* discriminant.
func (k claimKind) typeCode() uint16 {
	switch k {
	case kindInt64:
		return uapi.KACS_CLAIM_TYPE_INT64
	case kindUInt64:
		return uapi.KACS_CLAIM_TYPE_UINT64
	case kindBoolean:
		return uapi.KACS_CLAIM_TYPE_BOOLEAN
	case kindString:
		return uapi.KACS_CLAIM_TYPE_STRING
	case kindSID:
		return uapi.KACS_CLAIM_TYPE_SID
	case kindOctet:
		return uapi.KACS_CLAIM_TYPE_OCTET
	default:
		return 0
	}
}

// ClaimValue is one value of a claim attribute. Every value within a
// Claim must be the same kind. Build values with the constructors below.
type ClaimValue struct {
	kind claimKind
	i64  int64
	u64  uint64
	str  string
	sid  wire.SID
	oct  []byte
}

// Int64Value, UInt64Value, BoolValue, StringValue, SIDValue and
// OctetValue build the six claim-value kinds.
func Int64Value(n int64) ClaimValue   { return ClaimValue{kind: kindInt64, i64: n} }
func UInt64Value(n uint64) ClaimValue { return ClaimValue{kind: kindUInt64, u64: n} }
func StringValue(s string) ClaimValue { return ClaimValue{kind: kindString, str: s} }
func SIDValue(s wire.SID) ClaimValue  { return ClaimValue{kind: kindSID, sid: s} }
func OctetValue(b []byte) ClaimValue  { return ClaimValue{kind: kindOctet, oct: b} }

// BoolValue builds a boolean claim value.
func BoolValue(b bool) ClaimValue {
	var u uint64
	if b {
		u = 1
	}
	return ClaimValue{kind: kindBoolean, u64: u}
}

// Claim is a named, typed, multi-valued claim attribute — one resource
// attribute an object exposes, or one @Local claim passed to an access
// check.
type Claim struct {
	Name   string
	Flags  uint32
	Values []ClaimValue
}

// Encode emits one claim entry (PSD-004 §3.9) — the bare entry with no
// length prefix, i.e. the body of a resource-attribute ACE. It fails if
// the claim has no values or its values are not all the same kind.
func (c Claim) Encode() ([]byte, error) {
	if len(c.Values) == 0 {
		return nil, fmt.Errorf("libp/sd: claim %q has no values: %w", c.Name, ErrBadClaim)
	}
	kind := c.Values[0].kind
	for _, v := range c.Values {
		if v.kind != kind {
			return nil, fmt.Errorf("libp/sd: claim %q has mixed value kinds: %w", c.Name, ErrBadClaim)
		}
	}
	count := len(c.Values)

	// Fixed prefix: 16-byte header + a 4-byte value offset per value.
	payload := make([]byte, 16+count*4)
	nameOffset := uint32(len(payload))
	payload = append(append(payload, utf16le(c.Name)...), 0, 0) // UTF-16, NUL-terminated

	// Lay out the value slots. Inline kinds put their 8-byte datum in
	// the slot; indirect kinds put a u32 pointer and append the data.
	valueOffsets := make([]uint32, count)
	type indirect struct {
		slot int
		data []byte
	}
	var indirects []indirect
	for i, v := range c.Values {
		valueOffsets[i] = uint32(len(payload))
		switch v.kind {
		case kindInt64:
			payload = binary.LittleEndian.AppendUint64(payload, uint64(v.i64))
		case kindUInt64, kindBoolean:
			payload = binary.LittleEndian.AppendUint64(payload, v.u64)
		case kindString:
			indirects = append(indirects, indirect{len(payload), append(utf16le(v.str), 0, 0)})
			payload = binary.LittleEndian.AppendUint32(payload, 0)
		case kindSID:
			indirects = append(indirects, indirect{len(payload), v.sid.Bytes()})
			payload = binary.LittleEndian.AppendUint32(payload, 0)
		case kindOctet:
			blob := binary.LittleEndian.AppendUint32(nil, uint32(len(v.oct)))
			indirects = append(indirects, indirect{len(payload), append(blob, v.oct...)})
			payload = binary.LittleEndian.AppendUint32(payload, 0)
		}
	}

	// Append indirect data and backfill each slot's pointer.
	for _, ind := range indirects {
		binary.LittleEndian.PutUint32(payload[ind.slot:ind.slot+4], uint32(len(payload)))
		payload = append(payload, ind.data...)
	}

	// Backfill the header.
	binary.LittleEndian.PutUint32(payload[0:4], nameOffset)
	binary.LittleEndian.PutUint16(payload[4:6], kind.typeCode())
	binary.LittleEndian.PutUint32(payload[8:12], c.Flags)
	binary.LittleEndian.PutUint32(payload[12:16], uint32(count))
	for i, off := range valueOffsets {
		binary.LittleEndian.PutUint32(payload[16+i*4:20+i*4], off)
	}
	return payload, nil
}

// EncodeClaimsArray encodes a list of claims into the @Local claims-array
// wire form — each claim as a length-prefixed entry, concatenated. A nil
// or empty list encodes to nil.
func EncodeClaimsArray(claims []Claim) ([]byte, error) {
	var out []byte
	for _, c := range claims {
		entry, err := c.Encode()
		if err != nil {
			return nil, err
		}
		out = binary.LittleEndian.AppendUint32(out, uint32(len(entry)))
		out = append(out, entry...)
	}
	return out, nil
}
