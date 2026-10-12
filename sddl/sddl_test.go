package sddl

import (
	"bytes"
	"errors"
	"testing"

	"github.com/peios/libp-go/sd"
	"github.com/peios/libp-go/wire"
)

func mustParse(t *testing.T, s string, opts ...Option) sd.Descriptor {
	t.Helper()
	d, err := Parse(s, opts...)
	if err != nil {
		t.Fatalf("Parse(%q): %v", s, err)
	}
	return d
}

func TestSIDFromStringRoundTrip(t *testing.T) {
	for _, s := range []string{
		"S-1-1-0", "S-1-5-18", "S-1-5-32-544", "S-1-16-12288",
		"S-1-5-21-1004336348-1177238915-682003330-512", "S-1-15-2-1",
	} {
		sid, err := wire.SIDFromString(s)
		if err != nil {
			t.Fatalf("SIDFromString(%q): %v", s, err)
		}
		if got := sid.String(); got != s {
			t.Errorf("round trip: got %q, want %q", got, s)
		}
	}
}

func TestParseAlias(t *testing.T) {
	d := mustParse(t, "O:BAG:SY")
	if want := sd.BuiltinAdministrators.SID(); d.Owner != want {
		t.Errorf("owner = %v, want %v", d.Owner, want)
	}
	if want := sd.LocalSystem.SID(); d.Group != want {
		t.Errorf("group = %v, want %v", d.Group, want)
	}
}

func TestDomainAliasNeedsContext(t *testing.T) {
	if _, err := Parse("O:DA"); err == nil {
		t.Fatal("Parse(O:DA) with no domain context: want error, got nil")
	}
	dom, err := wire.SIDFromString("S-1-5-21-1-2-3")
	if err != nil {
		t.Fatal(err)
	}
	d := mustParse(t, "O:DA", WithDomain(dom))
	want, _ := dom.Child(512)
	if d.Owner != want {
		t.Errorf("owner = %v, want %v", d.Owner, want)
	}
	// A domain SID round-trips through Format when the context is given.
	out, err := Format(d, WithDomain(dom))
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	if out != "O:DA" {
		t.Errorf("Format = %q, want %q", out, "O:DA")
	}
}

func TestParseDocExample(t *testing.T) {
	const s = "O:BAG:BAD:P(A;;FA;;;BA)(A;;0x1200a9;;;BU)"
	d := mustParse(t, s)
	if d.DACL == nil {
		t.Fatal("DACL is nil")
	}
	if d.Control&sd.ControlDACLProtected == 0 {
		t.Error("DACL protected bit not set")
	}
	if len(d.DACL.Entries) != 2 {
		t.Fatalf("DACL has %d ACEs, want 2", len(d.DACL.Entries))
	}
	if a0 := d.DACL.Entries[0]; a0.Type != sd.AceAccessAllowed || a0.Mask != fileAll {
		t.Errorf("ACE 0 = {type %#x, mask %#x}, want allow / fileAll", a0.Type, a0.Mask)
	}
	if a1 := d.DACL.Entries[1]; a1.Mask != 0x1200a9 {
		t.Errorf("ACE 1 mask = %#x, want 0x1200a9", a1.Mask)
	}
}

func TestRoundTrip(t *testing.T) {
	inputs := []string{
		"O:BAG:BAD:P(A;;FA;;;BA)(A;;0x1200a9;;;BU)",
		"O:SYG:SYD:(A;OICI;0x1f01ff;;;SY)(D;;0x10000;;;WD)",
		"D:AI(A;ID;FR;;;AU)",
		"S:(AU;SAFA;0x1;;;WD)",
		"S:(ML;;NW;;;LW)",
		"G:BU",
	}
	for _, in := range inputs {
		d1 := mustParse(t, in)
		out, err := Format(d1)
		if err != nil {
			t.Fatalf("Format(parsed %q): %v", in, err)
		}
		d2 := mustParse(t, out)

		b1, err := d1.Marshal()
		if err != nil {
			t.Fatalf("Marshal(%q): %v", in, err)
		}
		b2, err := d2.Marshal()
		if err != nil {
			t.Fatalf("Marshal(reparsed %q): %v", out, err)
		}
		if !bytes.Equal(b1, b2) {
			t.Errorf("round trip %q -> %q changed the descriptor", in, out)
		}

		// Tie SDDL to the binary codec: marshal, re-parse the bytes,
		// and the SDDL rendering must be unchanged.
		d3, err := sd.ParseDescriptor(b1)
		if err != nil {
			t.Fatalf("ParseDescriptor(%q): %v", in, err)
		}
		out3, err := Format(d3)
		if err != nil {
			t.Fatalf("Format(binary %q): %v", in, err)
		}
		if out3 != out {
			t.Errorf("%q: format via binary = %q, want %q", in, out3, out)
		}
	}
}

func TestObjectACE(t *testing.T) {
	const guid = "11111111-2222-3333-4444-555555555555"
	d := mustParse(t, "D:(OA;;CCDC;"+guid+";;BA)")
	a := d.DACL.Entries[0]
	if a.Type != sd.AceAccessAllowedObject {
		t.Fatalf("type = %#x, want object-allowed", a.Type)
	}
	if a.ObjectType == nil {
		t.Fatal("ObjectType is nil")
	}
	if got := formatGUID(*a.ObjectType); got != guid {
		t.Errorf("GUID round trip: got %q, want %q", got, guid)
	}
	if a.Mask != 0x003 { // CC | DC
		t.Errorf("mask = %#x, want 0x3", a.Mask)
	}
}

func TestRejectUnsupportedACE(t *testing.T) {
	// Resource-attribute ACEs are still beyond the codec (callback ACEs
	// are covered by TestConditionalACE).
	_, err := Parse("D:(RA;;FR;;;BU)")
	if err == nil {
		t.Fatal("resource-attribute ACE: want error, got nil")
	}
	var se *SyntaxError
	if !errors.As(err, &se) {
		t.Errorf("error %v is not a *SyntaxError", err)
	}
}

func TestParseErrors(t *testing.T) {
	for _, bad := range []string{
		"X:BA",            // unknown component tag
		"O:",              // missing SID
		"O:ZZ",            // unknown alias
		"O:BAO:BA",        // duplicate component
		"D:(A;;FR;;;BA",   // unterminated ACE
		"D:(A;;FR;;BA)",   // too few fields
		"D:(A;;ZZ;;;BA)",  // unknown rights mnemonic
		"D:(A;;FR;g;;BA)", // malformed object GUID
		"D:(QQ;;FR;;;BA)", // unknown ACE type
	} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q): want error, got nil", bad)
		}
	}
}
