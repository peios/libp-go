package sddl

import (
	"bytes"
	"testing"

	"github.com/peios/libp-go/sd"
)

// TestConditionRoundTrip compiles each conditional expression to artx
// bytecode, decodes it back to text, recompiles, and checks the
// bytecode is unchanged.
func TestConditionRoundTrip(t *testing.T) {
	exprs := []string{
		`(@User.Title == "PM")`,
		`(@User.Level > 5)`,
		`(@Device.Managed != 0)`,
		`(Member_of {SID(BA)})`,
		`(Member_of_Any {SID(BA), SID(BU)})`,
		`(Not_Member_of {SID(BU)})`,
		`(Exists @User.Title)`,
		`(Not_Exists @Resource.Secret)`,
		`(!(@User.Banned == 1))`,
		`(@Resource.Dept Contains "eng")`,
		`((@User.a == 1) && (@User.b == 2))`,
		`((@User.a == 1) || (@Device.x == 2))`,
		`(Title == "local")`,
		`(@User.Group Any_of {SID(BA), SID(BU)})`,
	}
	for _, e := range exprs {
		c1, err := parseConditionText(e, options{})
		if err != nil {
			t.Errorf("parse %q: %v", e, err)
			continue
		}
		code := c1.Encode()
		text, err := decodeCondition(code, options{})
		if err != nil {
			t.Errorf("decode %q: %v", e, err)
			continue
		}
		c2, err := parseConditionText("("+text+")", options{})
		if err != nil {
			t.Errorf("reparse %q (decoded from %q): %v", text, e, err)
			continue
		}
		if !bytes.Equal(code, c2.Encode()) {
			t.Errorf("%q: round trip changed the bytecode (decoded text %q)", e, text)
		}
	}
}

// TestConditionalACE round-trips a callback ACE through SDDL text and
// through the binary descriptor codec.
func TestConditionalACE(t *testing.T) {
	const s = `O:BAD:(XA;;FR;;;WD;(@User.Title == "PM"))(XD;;FW;;;BU;(Member_of {SID(BA)}))`
	d := mustParse(t, s)
	if d.DACL == nil || len(d.DACL.Entries) != 2 {
		t.Fatalf("expected two DACL ACEs, got %v", d.DACL)
	}
	if d.DACL.Entries[0].Type != sd.AceAccessAllowedCallback {
		t.Errorf("ACE 0 type = %#x, want callback-allowed", d.DACL.Entries[0].Type)
	}
	if d.DACL.Entries[1].Type != sd.AceAccessDeniedCallback {
		t.Errorf("ACE 1 type = %#x, want callback-denied", d.DACL.Entries[1].Type)
	}

	out, err := Format(d)
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	d2 := mustParse(t, out)
	b1, err := d.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	b2, err := d2.Marshal()
	if err != nil {
		t.Fatalf("Marshal (reparsed): %v", err)
	}
	if !bytes.Equal(b1, b2) {
		t.Errorf("round trip changed the descriptor: %q -> %q", s, out)
	}

	// The same descriptor decoded from its binary form must render
	// identically.
	d3, err := sd.ParseDescriptor(b1)
	if err != nil {
		t.Fatalf("ParseDescriptor: %v", err)
	}
	out3, err := Format(d3)
	if err != nil {
		t.Fatalf("Format (from binary): %v", err)
	}
	if out3 != out {
		t.Errorf("format via binary = %q, want %q", out3, out)
	}
}

func TestRejectMalformedCondition(t *testing.T) {
	for _, bad := range []string{
		`D:(XA;;FR;;;WD;(@User.Title ==))`,     // missing right operand
		`D:(XA;;FR;;;WD;(@User.Title))`,        // no operator
		`D:(XA;;FR;;;WD;(@Bad.Class == 1))`,    // unknown attribute class
		`D:(XA;;FR;;;WD;(Member_of {SID(BA)))`, // unterminated brace
		`D:(XA;;FR;;;WD;())`,                   // empty expression
		`D:(XA;;FR;;;WD)`,                      // callback ACE missing the condition
	} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q): want error, got nil", bad)
		}
	}
}
