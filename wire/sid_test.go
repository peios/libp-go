package wire_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/peios/libp-go/wire"
)

// adminsSID is the binary encoding of S-1-5-32-544 (the well-known
// BUILTIN\Administrators SID): revision 1, two sub-authorities,
// identifier authority 5, sub-authorities 32 and 544.
var adminsSID = []byte{
	1, 2, 0, 0, 0, 0, 0, 5,
	0x20, 0, 0, 0,
	0x20, 0x02, 0, 0,
}

func TestParseSIDRoundTrip(t *testing.T) {
	sid, err := wire.ParseSID(adminsSID)
	if err != nil {
		t.Fatalf("ParseSID: %v", err)
	}
	if got, want := sid.String(), "S-1-5-32-544"; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
	if !sid.IsValid() {
		t.Fatal("IsValid() = false for a parsed SID")
	}
	if !bytes.Equal(sid.Bytes(), adminsSID) {
		t.Fatalf("Bytes() = %x, want %x", sid.Bytes(), adminsSID)
	}
}

func TestParseSIDTrailingBytesIgnored(t *testing.T) {
	buf := append(append([]byte{}, adminsSID...), 0xAA, 0xBB)
	sid, err := wire.ParseSID(buf)
	if err != nil {
		t.Fatalf("ParseSID: %v", err)
	}
	if got := len(sid.Bytes()); got != len(adminsSID) {
		t.Fatalf("Bytes() length = %d, want %d", got, len(adminsSID))
	}
}

func TestParseSIDRejectsMalformed(t *testing.T) {
	cases := map[string][]byte{
		"too short":                    {1, 0, 0},
		"bad revision":                 {2, 1, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0},
		"sub-authority count too high": {1, 16, 0, 0, 0, 0, 0, 5},
		"truncated sub-authorities":    {1, 2, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0},
	}
	for name, buf := range cases {
		if _, err := wire.ParseSID(buf); !errors.Is(err, wire.ErrBadSID) {
			t.Errorf("%s: want ErrBadSID, got %v", name, err)
		}
	}
}

func TestZeroSID(t *testing.T) {
	var s wire.SID
	if s.IsValid() {
		t.Error("zero SID IsValid() = true")
	}
	if s.String() != "S-?" {
		t.Errorf("zero SID String() = %q, want \"S-?\"", s.String())
	}
}
