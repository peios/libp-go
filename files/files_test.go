package files

import (
	"errors"
	"testing"

	"github.com/peios/libp-go/errno"
	uapi "github.com/peios/pkm/uapi/go"
)

// TestDispositionMapping checks every Disposition maps to its KACS
// create-disposition value — a pure check, runs anywhere. A wrong
// mapping here would silently open with the wrong create semantics.
func TestDispositionMapping(t *testing.T) {
	cases := []struct {
		d    Disposition
		want uint32
	}{
		{DispOpen, uapi.KACS_DISPOSITION_OPEN},
		{DispCreate, uapi.KACS_DISPOSITION_CREATE},
		{DispOpenIf, uapi.KACS_DISPOSITION_OPEN_IF},
		{DispSupersede, uapi.KACS_DISPOSITION_SUPERSEDE},
		{DispOverwrite, uapi.KACS_DISPOSITION_OVERWRITE},
		{DispOverwriteIf, uapi.KACS_DISPOSITION_OVERWRITE_IF},
	}
	for _, c := range cases {
		got, ok := c.d.kacs()
		if !ok || got != c.want {
			t.Errorf("Disposition(%d).kacs() = (%d, %v), want (%d, true)", c.d, got, ok, c.want)
		}
	}
	if _, ok := Disposition(99).kacs(); ok {
		t.Error("Disposition(99).kacs(): ok = true, want false")
	}
}

// TestZeroOptionsOpensExisting locks the safety invariant: a zero
// OpenOptions opens an existing file rather than creating or truncating.
func TestZeroOptionsOpensExisting(t *testing.T) {
	var o OpenOptions
	if o.Disposition != DispOpen {
		t.Fatalf("zero OpenOptions: disposition = %d, want DispOpen", o.Disposition)
	}
}

// TestOpenRootDirectory round-trips a real kacs_open syscall: open the
// root directory read-only. It skips when not on a Peios kernel.
func TestOpenRootDirectory(t *testing.T) {
	fh, status, err := Open("/", OpenOptions{
		Access:      ListDirectory,
		Disposition: DispOpen,
		Directory:   true,
	})
	if errors.Is(err, errno.ENOSYS) {
		t.Skip("kacs_open unavailable — not a Peios kernel")
	}
	if err != nil {
		t.Fatalf("Open(/): %v", err)
	}
	defer fh.Close()
	if status != StatusOpened {
		t.Fatalf("Open(/): status = %d, want StatusOpened", status)
	}
	if fh.FD() < 0 {
		t.Fatalf("Open(/): invalid fd %d", fh.FD())
	}
}
