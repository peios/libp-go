package event_test

import (
	"errors"
	"runtime"
	"testing"

	"github.com/peios/libp-go/errno"
	"github.com/peios/libp-go/event"
)

// TestOriginString is a pure check of the origin-class names.
func TestOriginString(t *testing.T) {
	cases := map[event.Origin]string{
		event.OriginUserspace: "USER",
		event.OriginKMES:      "KMES",
		event.OriginKACS:      "KACS",
		event.OriginLCS:       "LCS",
		event.Origin(200):     "????",
	}
	for o, want := range cases {
		if got := o.String(); got != want {
			t.Errorf("Origin(%d).String() = %q, want %q", o, got, want)
		}
	}
}

// skipKMES skips the test when KMES is unavailable: ENOSYS off a Peios
// kernel, or EPERM/EACCES when the test token lacks the KMES privileges.
func skipKMES(t *testing.T, err error) bool {
	switch {
	case errors.Is(err, errno.ENOSYS):
		t.Skip("KMES syscalls unavailable — not a Peios kernel")
	case errors.Is(err, errno.EPERM), errors.Is(err, errno.EACCES):
		t.Skip("KMES needs SeSecurityPrivilege / SeAuditPrivilege — not held here")
	default:
		return false
	}
	return true
}

// TestEmitAttachDrain round-trips a real KMES event: attach the per-CPU
// ring buffers, emit a uniquely-tagged event, and drain it back.
func TestEmitAttachDrain(t *testing.T) {
	rings, err := event.AttachAll()
	if skipKMES(t, err) {
		return
	}
	if err != nil {
		t.Fatalf("AttachAll: %v", err)
	}
	defer func() {
		for _, r := range rings {
			r.Close()
		}
	}()
	if len(rings) == 0 {
		t.Fatal("AttachAll returned no rings")
	}

	// Emit lands on the current CPU's ring — pin the thread so the emit
	// and the drain stay coherent.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	const tag = "libp.event.selftest"
	if err := event.Emit(tag, []byte{0x01}); err != nil {
		if skipKMES(t, err) {
			return
		}
		t.Fatalf("Emit: %v", err)
	}

	// Drain every ring; the event is in whichever one serves this CPU.
	for _, r := range rings {
		for {
			ev, ok, err := r.Next()
			if err != nil {
				t.Fatalf("ring %d Next: %v", r.CPUID(), err)
			}
			if !ok {
				break
			}
			if string(ev.EventType) == tag {
				return // round-trip confirmed
			}
		}
	}
	t.Fatalf("emitted event %q not found in any ring", tag)
}
