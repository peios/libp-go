package sd_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/peios/libp-go/errno"
	"github.com/peios/libp-go/sd"
)

func TestStripInheritedACEs(t *testing.T) {
	explicit := sd.Allow(sd.Everyone.SID(), sd.GenericRead)

	inherited := sd.Allow(sd.LocalSystem.SID(), sd.GenericAll)
	inherited.Flags = sd.FlagInherited
	inheritedDeny := sd.Deny(sd.Everyone.SID(), sd.GenericWrite)
	inheritedDeny.Flags = sd.FlagInherited

	d := sd.Descriptor{
		Owner: sd.LocalSystem.SID(),
		DACL:  &sd.ACL{Entries: []sd.ACE{explicit, inherited, inheritedDeny}},
	}
	raw, err := d.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	stripped, err := sd.StripInheritedACEs(raw, sd.InfoDACL)
	if err != nil {
		t.Fatalf("StripInheritedACEs: %v", err)
	}
	got, err := sd.ParseDescriptor(stripped)
	if err != nil {
		t.Fatalf("ParseDescriptor: %v", err)
	}
	if got.DACL == nil || len(got.DACL.Entries) != 1 {
		t.Fatalf("DACL after strip: %+v", got.DACL)
	}
	if got.DACL.Entries[0].SID != sd.Everyone.SID() {
		t.Error("the explicit ACE did not survive the strip")
	}
	if got.Owner != sd.LocalSystem.SID() {
		t.Error("owner was not preserved")
	}
}

func TestStripInheritedNoneSelected(t *testing.T) {
	d := sd.Descriptor{Owner: sd.LocalSystem.SID()}
	raw, err := d.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	// InfoOwner selects neither DACL nor SACL — the SD comes back as-is.
	out, err := sd.StripInheritedACEs(raw, sd.InfoOwner)
	if err != nil {
		t.Fatalf("StripInheritedACEs: %v", err)
	}
	if !bytes.Equal(out, raw) {
		t.Error("a non-DACL/SACL strip changed the descriptor")
	}
}

// TestGetSDRoot round-trips a real kacs_get_sd syscall against the root
// directory. It skips when not on a Peios kernel, or when the test token
// lacks the rights to read /'s descriptor.
func TestGetSDRoot(t *testing.T) {
	raw, err := sd.GetSD(sd.Path("/"), sd.InfoOwner|sd.InfoGroup|sd.InfoDACL)
	switch {
	case errors.Is(err, errno.ENOSYS):
		t.Skip("kacs_get_sd unavailable — not a Peios kernel")
	case errors.Is(err, errno.EACCES), errors.Is(err, errno.EPERM):
		t.Skip("reading /'s security descriptor was denied here")
	case err != nil:
		t.Fatalf("GetSD(/): %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("GetSD(/) returned no bytes")
	}
	if _, err := sd.ParseDescriptor(raw); err != nil {
		t.Fatalf("ParseDescriptor of /'s SD: %v", err)
	}
}
