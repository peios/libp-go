package sd_test

import (
	"encoding/binary"
	"testing"

	"github.com/peios/libp-go/sd"
)

func TestConditionEncode(t *testing.T) {
	c := sd.Exists(sd.UserAttr("dept"))
	b := c.Encode()
	if string(b[:4]) != "artx" {
		t.Fatalf("missing artx magic: %x", b[:4])
	}
	if len(b)%4 != 0 {
		t.Fatalf("conditional bytecode not DWORD-padded: len %d", len(b))
	}

	// A compound expression composes and still encodes cleanly.
	compound := sd.Compare(sd.OpGreaterEqual,
		sd.UserAttr("clearance"), sd.ResourceAttr("level")).
		And(sd.Exists(sd.UserAttr("dept"))).
		Not()
	cb := compound.Encode()
	if string(cb[:4]) != "artx" || len(cb)%4 != 0 {
		t.Fatalf("compound condition encoded badly: %x", cb)
	}
}

func TestClaimEncode(t *testing.T) {
	c := sd.Claim{Name: "Level", Values: []sd.ClaimValue{sd.Int64Value(7)}}
	b, err := c.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if vt := binary.LittleEndian.Uint16(b[4:6]); vt != 1 { // CLAIM_TYPE_INT64
		t.Errorf("value_type = %d, want 1", vt)
	}
	if n := binary.LittleEndian.Uint32(b[12:16]); n != 1 {
		t.Errorf("value_count = %d, want 1", n)
	}

	if _, err := (sd.Claim{Name: "x"}).Encode(); err == nil {
		t.Error("empty claim: want error")
	}
	mixed := sd.Claim{Name: "x", Values: []sd.ClaimValue{sd.Int64Value(1), sd.BoolValue(true)}}
	if _, err := mixed.Encode(); err == nil {
		t.Error("mixed-kind claim: want error")
	}
}

func TestEncodeObjectTree(t *testing.T) {
	tree := sd.EncodeObjectTree([]sd.ObjectNode{
		{Level: 0, GUID: sd.GUID{0x11}},
		{Level: 1, GUID: sd.GUID{0x22}},
	})
	if len(tree) != 40 {
		t.Fatalf("object tree = %d bytes, want 40", len(tree))
	}
	if lvl := binary.LittleEndian.Uint16(tree[20:22]); lvl != 1 {
		t.Errorf("node 1 level = %d, want 1", lvl)
	}
	if sd.EncodeObjectTree(nil) != nil {
		t.Error("empty object tree should encode to nil")
	}
}

func TestCallbackAndResourceACE(t *testing.T) {
	cond := sd.Compare(sd.OpEqual, sd.UserAttr("dept"), sd.StringOperand("eng"))
	raw, err := sd.AllowCallback(sd.Everyone.SID(), sd.GenericRead, cond).Marshal()
	if err != nil {
		t.Fatalf("AllowCallback Marshal: %v", err)
	}
	got, _, err := sd.ParseACE(raw)
	if err != nil {
		t.Fatalf("ParseACE: %v", err)
	}
	if got.Type != sd.AceAccessAllowedCallback {
		t.Errorf("callback type = 0x%02x", byte(got.Type))
	}
	if got.Raw == nil {
		t.Error("callback ACE should round-trip through Raw")
	}

	ra, err := sd.ResourceAttribute(sd.Claim{
		Name:   "Confidentiality",
		Values: []sd.ClaimValue{sd.Int64Value(3)},
	})
	if err != nil {
		t.Fatalf("ResourceAttribute: %v", err)
	}
	if ra.Type != sd.AceSystemResourceAttribute {
		t.Errorf("resource-attribute type = 0x%02x", byte(ra.Type))
	}
	if _, err := ra.Marshal(); err != nil {
		t.Fatalf("ResourceAttribute Marshal: %v", err)
	}
}
