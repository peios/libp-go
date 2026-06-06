package token_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/peios/libp-go/errno"
	"github.com/peios/libp-go/token"
)

// TestOpenSelf round-trips a real kacs_open_self_token syscall: open the
// calling task's effective token, then release it. It skips when not run
// on a Peios kernel (the syscall returns ENOSYS there).
func TestOpenSelf(t *testing.T) {
	tok, err := token.OpenSelf(0, token.Query)
	if errors.Is(err, errno.ENOSYS) {
		t.Skip("kacs_open_self_token unavailable — not a Peios kernel")
	}
	if err != nil {
		t.Fatalf("OpenSelf: %v", err)
	}
	defer tok.Close()
	if tok.FD() < 0 {
		t.Fatalf("OpenSelf returned an invalid fd: %d", tok.FD())
	}
}

// TestOpenSelfZeroAccessRejected confirms the errno path: the kernel
// rejects a zero access mask with EINVAL, surfaced as an errno.Errno
// through errors.Is.
func TestOpenSelfZeroAccessRejected(t *testing.T) {
	_, err := token.OpenSelf(0, 0)
	if errors.Is(err, errno.ENOSYS) {
		t.Skip("kacs_open_self_token unavailable — not a Peios kernel")
	}
	if !errors.Is(err, errno.EINVAL) {
		t.Fatalf("OpenSelf(0, 0): want EINVAL, got %v", err)
	}
}

// TestSelfTokenType opens the caller's token and queries its type — it
// exercises the KACS_IOC_QUERY ioctl path. A process that is not
// impersonating has a primary effective token.
func TestSelfTokenType(t *testing.T) {
	tok := openSelfOrSkip(t)
	defer tok.Close()
	typ, err := tok.TokenType()
	if err != nil {
		t.Fatalf("TokenType: %v", err)
	}
	if typ != token.TypePrimary {
		t.Fatalf("TokenType: want TypePrimary, got %d", typ)
	}
}

// TestSelfUserSID opens the caller's token and reads its user SID,
// exercising a query class that decodes through wire.ParseSID.
func TestSelfUserSID(t *testing.T) {
	tok := openSelfOrSkip(t)
	defer tok.Close()
	sid, err := tok.UserSID()
	if err != nil {
		t.Fatalf("UserSID: %v", err)
	}
	if !sid.IsValid() {
		t.Fatal("UserSID returned an invalid SID")
	}
	if !strings.HasPrefix(sid.String(), "S-1-") {
		t.Fatalf("UserSID string %q is not a SID", sid.String())
	}
}

// openSelfOrSkip opens the caller's token with query access, skipping
// the test when not on a Peios kernel.
func openSelfOrSkip(t *testing.T) *token.Token {
	t.Helper()
	tok, err := token.OpenSelf(0, token.Query)
	if errors.Is(err, errno.ENOSYS) {
		t.Skip("KACS token syscalls unavailable — not a Peios kernel")
	}
	if err != nil {
		t.Fatalf("OpenSelf: %v", err)
	}
	return tok
}
