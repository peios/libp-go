// Package wire holds hand-written codecs for the Peios on-wire formats —
// SIDs today, and security descriptors, ACLs/ACEs and the KMES event
// header as those domains land.
//
// These are algorithms over the raw bytes the kernel ABI exchanges, not
// mechanical transcription, so they live here rather than in the
// generated uapi tier. See libp-design.md §2.6.
package wire

import (
	"errors"
	"strconv"
	"strings"
)

// maxSubAuthorities is the largest sub-authority count a valid SID may
// declare (KACS_SID_MAX_SUB_AUTHORITIES).
const maxSubAuthorities = 15

// maxSIDBytes is the encoded size of the largest valid SID: an 8-byte
// header plus maxSubAuthorities 4-byte sub-authorities.
const maxSIDBytes = 8 + 4*maxSubAuthorities

// ErrBadSID reports a buffer that is not a well-formed binary SID.
var ErrBadSID = errors.New("libp/wire: malformed SID")

// SID is a security identifier — the unit of identity KACS works in
// (MS-DTYP 2.4.2). uid/gid are meaningless on Peios; a SID is not.
//
// SID is a fixed-size, pointer-free value type: comparable, usable as a
// map key, allocation-free to copy, and immutable from outside this
// package. It stores the canonical binary SID encoding inline. A SID is
// variable-length but bounded — sub_authority_count caps at 15, so 68
// bytes holds any valid SID — and bytes past the encoded length are kept
// zero, so == is a correct equality test. The zero value is the invalid
// SID; see IsValid.
type SID struct {
	raw [maxSIDBytes]byte
}

// ParseSID decodes a binary SID from the start of buf. Bytes beyond the
// SID are ignored. It returns ErrBadSID if buf does not begin with a
// well-formed SID.
func ParseSID(buf []byte) (SID, error) {
	if len(buf) < 8 || buf[0] != 1 { // revision is always 1
		return SID{}, ErrBadSID
	}
	count := int(buf[1])
	if count > maxSubAuthorities {
		return SID{}, ErrBadSID
	}
	n := 8 + 4*count
	if len(buf) < n {
		return SID{}, ErrBadSID
	}
	// Copy into a zero value: the tail past n stays zero, so two equal
	// SIDs hold identical arrays and == compares them correctly.
	var s SID
	copy(s.raw[:], buf[:n])
	return s, nil
}

// NewSID builds a SID from its 48-bit identifier authority and its
// sub-authorities (the revision is always 1). It returns ErrBadSID if
// more than 15 sub-authorities are supplied.
func NewSID(authority uint64, subAuthorities ...uint32) (SID, error) {
	if len(subAuthorities) > maxSubAuthorities {
		return SID{}, ErrBadSID
	}
	var s SID
	s.raw[0] = 1
	s.raw[1] = byte(len(subAuthorities))
	// 48-bit identifier authority, big-endian, bytes [2:8].
	for i := range 6 {
		s.raw[2+i] = byte(authority >> (8 * (5 - i)))
	}
	for i, sa := range subAuthorities {
		off := 8 + 4*i
		s.raw[off] = byte(sa)
		s.raw[off+1] = byte(sa >> 8)
		s.raw[off+2] = byte(sa >> 16)
		s.raw[off+3] = byte(sa >> 24)
	}
	return s, nil
}

// SIDFromString parses the standard "S-1-…" textual SID form — the
// inverse of String. The revision component must be 1; the identifier
// authority may be decimal or, where it needs the range, "0x"-prefixed
// hex; each sub-authority is a decimal uint32. Any other shape yields
// ErrBadSID.
func SIDFromString(s string) (SID, error) {
	parts := strings.Split(s, "-")
	if len(parts) < 3 || parts[0] != "S" || parts[1] != "1" {
		return SID{}, ErrBadSID
	}
	var (
		authority uint64
		err       error
	)
	if a := parts[2]; len(a) > 2 && (a[:2] == "0x" || a[:2] == "0X") {
		authority, err = strconv.ParseUint(a[2:], 16, 48)
	} else {
		authority, err = strconv.ParseUint(parts[2], 10, 48)
	}
	if err != nil {
		return SID{}, ErrBadSID
	}
	subs := make([]uint32, 0, len(parts)-3)
	for _, p := range parts[3:] {
		v, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return SID{}, ErrBadSID
		}
		subs = append(subs, uint32(v))
	}
	return NewSID(authority, subs...)
}

// Child derives a principal SID from a domain or machine SID by
// appending rid as a further sub-authority — the standard
// domain-SID-plus-RID composition. It returns ErrBadSID if s is the
// invalid SID or already holds the maximum 15 sub-authorities.
func (s SID) Child(rid uint32) (SID, error) {
	if !s.IsValid() {
		return SID{}, ErrBadSID
	}
	count := int(s.raw[1])
	if count >= maxSubAuthorities {
		return SID{}, ErrBadSID
	}
	child := s
	off := 8 + 4*count
	child.raw[off] = byte(rid)
	child.raw[off+1] = byte(rid >> 8)
	child.raw[off+2] = byte(rid >> 16)
	child.raw[off+3] = byte(rid >> 24)
	child.raw[1] = byte(count + 1)
	return child, nil
}

// IsValid reports whether s holds a SID. The zero SID is not valid.
func (s SID) IsValid() bool { return s.raw[0] == 1 }

// Bytes returns a fresh copy of the canonical binary SID encoding, or
// nil for the invalid SID.
func (s SID) Bytes() []byte {
	if !s.IsValid() {
		return nil
	}
	n := 8 + 4*int(s.raw[1])
	out := make([]byte, n)
	copy(out, s.raw[:n])
	return out
}

// String renders the SID in the standard "S-1-..." textual form, or
// "S-?" for the invalid SID.
func (s SID) String() string {
	if !s.IsValid() {
		return "S-?"
	}
	count := int(s.raw[1])

	// 48-bit identifier authority, big-endian, bytes [2:8].
	var auth uint64
	for _, x := range s.raw[2:8] {
		auth = auth<<8 | uint64(x)
	}

	var sb strings.Builder
	sb.WriteString("S-1-")
	if auth >= 1<<32 {
		sb.WriteString("0x")
		sb.WriteString(strconv.FormatUint(auth, 16))
	} else {
		sb.WriteString(strconv.FormatUint(auth, 10))
	}
	for i := range count {
		off := 8 + 4*i
		sub := uint32(s.raw[off]) | uint32(s.raw[off+1])<<8 |
			uint32(s.raw[off+2])<<16 | uint32(s.raw[off+3])<<24
		sb.WriteByte('-')
		sb.WriteString(strconv.FormatUint(uint64(sub), 10))
	}
	return sb.String()
}
