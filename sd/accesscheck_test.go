package sd_test

import (
	"errors"
	"testing"

	"github.com/peios/libp-go/errno"
	"github.com/peios/libp-go/sd"
)

// TestAccessCheck round-trips a real kacs_access_check syscall against
// the caller's own effective token (a nil CheckRequest.Token) and a
// synthetic descriptor. It skips off a Peios kernel. The test asserts
// the ABI round-trips and yields a Decision — not a particular grant
// outcome, which is KACS's to decide.
func TestAccessCheck(t *testing.T) {
	sdBytes, err := sd.Descriptor{
		Owner: sd.LocalSystem.SID(),
		Group: sd.BuiltinAdministrators.SID(),
		DACL: &sd.ACL{Entries: []sd.ACE{
			sd.Allow(sd.Everyone.SID(), sd.AccessReadControl),
		}},
	}.Marshal()
	if err != nil {
		t.Fatalf("Marshal SD: %v", err)
	}

	// Token nil → the caller's own effective token.
	dec, err := sd.Check(sd.CheckRequest{
		SD:            sdBytes,
		DesiredAccess: sd.AccessReadControl,
	})
	if errors.Is(err, errno.ENOSYS) {
		t.Skip("kacs_access_check unavailable — not a Peios kernel")
	}
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	t.Logf("access check round-tripped: granted=%v mask=0x%x", dec.Granted, dec.GrantedMask)
}
