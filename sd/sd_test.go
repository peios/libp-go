package sd_test

import (
	"bytes"
	"testing"

	"github.com/peios/libp-go/sd"
	"github.com/peios/libp-go/wire"
)

func TestWellKnownSID(t *testing.T) {
	s := sd.LocalSystem.SID()
	if got := s.String(); got != "S-1-5-18" {
		t.Fatalf("LocalSystem SID = %q, want S-1-5-18", got)
	}
	w, ok := sd.LookupWellKnown(s)
	if !ok || w != sd.LocalSystem {
		t.Fatalf("LookupWellKnown(LocalSystem) = (%v, %v)", w, ok)
	}
	other, _ := wire.NewSID(5, 21, 1, 2, 3)
	if w, ok := sd.LookupWellKnown(other); ok {
		t.Errorf("LookupWellKnown(domain SID) matched %v", w)
	}
}

func TestDescriptorRoundTrip(t *testing.T) {
	d := sd.Descriptor{
		Control: sd.ControlDACLProtected,
		Owner:   sd.LocalSystem.SID(),
		Group:   sd.BuiltinAdministrators.SID(),
		DACL: &sd.ACL{Entries: []sd.ACE{
			sd.Allow(sd.Everyone.SID(), sd.GenericRead),
			sd.Deny(sd.Everyone.SID(), sd.GenericWrite),
		}},
	}
	raw, err := d.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := sd.ParseDescriptor(raw)
	if err != nil {
		t.Fatalf("ParseDescriptor: %v", err)
	}
	if got.Owner != d.Owner || got.Group != d.Group {
		t.Errorf("owner/group mismatch: %v / %v", got.Owner, got.Group)
	}
	if got.Control&sd.ControlSelfRelative == 0 {
		t.Error("SELF_RELATIVE not set by Marshal")
	}
	if got.Control&sd.ControlDACLProtected == 0 {
		t.Error("DACL_PROTECTED control bit lost")
	}
	if got.DACL == nil || len(got.DACL.Entries) != 2 {
		t.Fatalf("DACL round-trip wrong: %+v", got.DACL)
	}
	if a := got.DACL.Entries[0]; a.Type != sd.AceAccessAllowed ||
		a.Mask != sd.GenericRead || a.SID != sd.Everyone.SID() {
		t.Errorf("ACE 0 wrong: %+v", a)
	}
	if a := got.DACL.Entries[1]; a.Type != sd.AceAccessDenied || a.Mask != sd.GenericWrite {
		t.Errorf("ACE 1 wrong: %+v", a)
	}
}

func TestObjectACERoundTrip(t *testing.T) {
	ot := sd.GUID{0x11, 0x22, 0x33}
	raw, err := sd.AllowObject(sd.Everyone.SID(), sd.GenericRead, &ot, nil).Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, n, err := sd.ParseACE(raw)
	if err != nil {
		t.Fatalf("ParseACE: %v", err)
	}
	if n != len(raw) {
		t.Errorf("ParseACE consumed %d, want %d", n, len(raw))
	}
	if got.Type != sd.AceAccessAllowedObject {
		t.Errorf("type = 0x%02x", byte(got.Type))
	}
	if got.ObjectType == nil || *got.ObjectType != ot {
		t.Errorf("ObjectType lost: %v", got.ObjectType)
	}
	if got.InheritedObjectType != nil {
		t.Errorf("unexpected InheritedObjectType: %v", got.InheritedObjectType)
	}
	if got.SID != sd.Everyone.SID() {
		t.Errorf("SID lost")
	}
}

func TestRawACERoundTrip(t *testing.T) {
	body := []byte{0xde, 0xad, 0xbe, 0xef}
	raw, err := sd.RawACE(sd.AceSystemResourceAttribute, body).Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, _, err := sd.ParseACE(raw)
	if err != nil {
		t.Fatalf("ParseACE: %v", err)
	}
	if got.Type != sd.AceSystemResourceAttribute {
		t.Errorf("type = 0x%02x", byte(got.Type))
	}
	if !bytes.Equal(got.Raw, body) {
		t.Errorf("Raw = %x, want %x", got.Raw, body)
	}
}
