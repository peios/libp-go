package sd_test

import (
	"testing"

	"github.com/peios/libp-go/sd"
)

func TestComputeInheritedACEs(t *testing.T) {
	// An OBJECT_INHERIT ACE, inherited by a file child: all four
	// inheritance flags clear, INHERITED set.
	oi := sd.Allow(sd.Everyone.SID(), sd.GenericRead)
	oi.Flags = sd.FlagObjectInherit
	got := sd.ComputeInheritedACEs(sd.ACL{Entries: []sd.ACE{oi}}, false)
	if len(got) != 1 {
		t.Fatalf("OI to file: %d ACEs, want 1", len(got))
	}
	f := got[0].Flags
	if f&sd.FlagInherited == 0 {
		t.Error("inherited ACE is missing FlagInherited")
	}
	const inheritFlags = sd.FlagObjectInherit | sd.FlagContainerInherit |
		sd.FlagNoPropagateInherit | sd.FlagInheritOnly
	if f&inheritFlags != 0 {
		t.Errorf("file-child ACE kept inheritance flags: 0x%02x", byte(f))
	}

	// A CONTAINER_INHERIT-only ACE inherited by a file child: nothing.
	ci := sd.Allow(sd.Everyone.SID(), sd.GenericRead)
	ci.Flags = sd.FlagContainerInherit
	if got := sd.ComputeInheritedACEs(sd.ACL{Entries: []sd.ACE{ci}}, false); len(got) != 0 {
		t.Errorf("CI-only to file: %d ACEs, want 0", len(got))
	}
}

func TestReinherit(t *testing.T) {
	// Parent DACL: an OI+CI allow ACE.
	pace := sd.Allow(sd.Everyone.SID(), sd.GenericRead)
	pace.Flags = sd.FlagObjectInherit | sd.FlagContainerInherit
	parent, err := sd.Descriptor{DACL: &sd.ACL{Entries: []sd.ACE{pace}}}.Marshal()
	if err != nil {
		t.Fatalf("parent Marshal: %v", err)
	}

	// Child DACL: one explicit ACE, plus a stale inherited ACE.
	stale := sd.Allow(sd.LocalSystem.SID(), sd.GenericAll)
	stale.Flags = sd.FlagInherited
	child, err := sd.Descriptor{DACL: &sd.ACL{Entries: []sd.ACE{
		sd.Allow(sd.Anonymous.SID(), sd.GenericAll),
		stale,
	}}}.Marshal()
	if err != nil {
		t.Fatalf("child Marshal: %v", err)
	}

	out, err := sd.Reinherit(parent, child, false)
	if err != nil {
		t.Fatalf("Reinherit: %v", err)
	}
	d, err := sd.ParseDescriptor(out)
	if err != nil {
		t.Fatalf("ParseDescriptor: %v", err)
	}
	if d.DACL == nil || len(d.DACL.Entries) != 2 {
		t.Fatalf("DACL after reinherit: %+v", d.DACL)
	}
	// Explicit ACE first (no INHERITED), the freshly inherited one second.
	if d.DACL.Entries[0].Flags&sd.FlagInherited != 0 {
		t.Error("first ACE should be the explicit one")
	}
	if d.DACL.Entries[1].Flags&sd.FlagInherited == 0 {
		t.Error("second ACE should be freshly inherited")
	}
	if d.DACL.Entries[1].SID != sd.Everyone.SID() {
		t.Error("inherited ACE should carry the parent ACE's SID")
	}
}
