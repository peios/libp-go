package sd

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrBadACL reports a buffer that is not a well-formed ACL.
var ErrBadACL = errors.New("libp/sd: malformed ACL")

// ACL revisions: the standard revision, and the directory-services
// revision required once an object-type or callback ACE is present.
const (
	aclRevision   = 2
	aclRevisionDS = 4
)

// ACL is an access-control list — an ordered list of ACEs. An empty DACL
// denies everyone; an empty SACL audits nothing — both are meaningful,
// and distinct from an absent ACL (a nil *ACL on a Descriptor).
type ACL struct {
	Entries []ACE
}

// Marshal emits the ACL's wire bytes: an 8-byte header then the ACEs.
// The ACL revision is chosen automatically.
func (l ACL) Marshal() ([]byte, error) {
	if len(l.Entries) > 0xFFFF {
		return nil, fmt.Errorf("libp/sd: ACL has %d ACEs, exceeds 65535", len(l.Entries))
	}
	var aces []byte
	ds := false
	for i := range l.Entries {
		b, err := l.Entries[i].Marshal()
		if err != nil {
			return nil, err
		}
		aces = append(aces, b...)
		if l.Entries[i].Type.needsDSRevision() {
			ds = true
		}
	}
	size := 8 + len(aces)
	if size > 0xFFFF {
		return nil, fmt.Errorf("libp/sd: ACL wire size %d exceeds 65535", size)
	}
	out := make([]byte, 8, size)
	if ds {
		out[0] = aclRevisionDS
	} else {
		out[0] = aclRevision
	}
	binary.LittleEndian.PutUint16(out[2:], uint16(size))
	binary.LittleEndian.PutUint16(out[4:], uint16(len(l.Entries)))
	return append(out, aces...), nil
}

// ParseACL decodes an ACL from the start of buf.
func ParseACL(buf []byte) (ACL, error) {
	if len(buf) < 8 {
		return ACL{}, ErrBadACL
	}
	size := int(binary.LittleEndian.Uint16(buf[2:4]))
	count := int(binary.LittleEndian.Uint16(buf[4:6]))
	if size < 8 || size > len(buf) {
		return ACL{}, ErrBadACL
	}
	rest := buf[8:size]
	entries := make([]ACE, 0, count)
	for range count {
		a, n, err := ParseACE(rest)
		if err != nil {
			return ACL{}, err
		}
		entries = append(entries, a)
		rest = rest[n:]
	}
	return ACL{Entries: entries}, nil
}
