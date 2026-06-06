package event

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/peios/libp-go/internal/sys"
	uapi "github.com/peios/pkm/uapi/go"
)

// Emit emits a single event into KMES. eventType is an arbitrary UTF-8
// type tag; payload must be a msgpack-encoded value (the kernel rejects
// a non-msgpack or empty payload with EINVAL). The caller's effective
// token must hold SeAuditPrivilege.
//
// The event lands in the ring buffer of whichever CPU the calling thread
// is running on.
func Emit(eventType string, payload []byte) error {
	et := []byte(eventType)
	if len(et) > 0xFFFF {
		return fmt.Errorf("libp/event: emit: event type too long for the KMES ABI")
	}
	if uint64(len(payload)) > 0xFFFFFFFF {
		return fmt.Errorf("libp/event: emit: payload too long for the KMES ABI")
	}
	var etPtr, plPtr unsafe.Pointer
	if len(et) > 0 {
		etPtr = unsafe.Pointer(&et[0])
	}
	if len(payload) > 0 {
		plPtr = unsafe.Pointer(&payload[0])
	}
	_, err := retry(func() (uintptr, syscall.Errno) {
		_, _, e := syscall.Syscall6(uapi.SYS_KMES_EMIT,
			uintptr(etPtr), uintptr(len(et)),
			uintptr(plPtr), uintptr(len(payload)), 0, 0)
		return 0, e
	})
	runtime.KeepAlive(et)
	runtime.KeepAlive(payload)
	if err != nil {
		return fmt.Errorf("libp/event: emit: %w", err)
	}
	return nil
}

// EmitEntry is one event to emit as part of an EmitBatch call.
type EmitEntry struct {
	EventType string
	Payload   []byte
}

// EmitBatch emits several events in a single kmes_emit_batch syscall.
// All events share one timestamp and amortise the privilege check and
// notification over the batch. entries must hold 1..256 events.
//
// The kernel processes entries in order and stops at the first rejected
// one; if entry N fails, entries 0..N are emitted and the returned error
// reports how many were accepted.
func EmitBatch(entries []EmitEntry) error {
	if len(entries) == 0 || len(entries) > int(uapi.KMES_BATCH_MAX_ENTRIES) {
		return fmt.Errorf("libp/event: emit batch: want 1..%d entries, got %d",
			uapi.KMES_BATCH_MAX_ENTRIES, len(entries))
	}
	raw := make([]uapi.Kmes_emit_entry, len(entries))
	types := make([][]byte, len(entries))
	for i := range entries {
		et := []byte(entries[i].EventType)
		if len(et) > 0xFFFF {
			return fmt.Errorf("libp/event: emit batch: entry %d event type too long", i)
		}
		if uint64(len(entries[i].Payload)) > 0xFFFFFFFF {
			return fmt.Errorf("libp/event: emit batch: entry %d payload too long", i)
		}
		types[i] = et
		var etPtr, plPtr uint64
		if len(et) > 0 {
			etPtr = uint64(uintptr(unsafe.Pointer(&et[0])))
		}
		if len(entries[i].Payload) > 0 {
			plPtr = uint64(uintptr(unsafe.Pointer(&entries[i].Payload[0])))
		}
		raw[i] = uapi.Kmes_emit_entry{
			Event_type:     etPtr,
			Event_type_len: uint16(len(et)),
			Payload:        plPtr,
			Payload_len:    uint32(len(entries[i].Payload)),
		}
	}

	var emitted uint32
	_, err := retry(func() (uintptr, syscall.Errno) {
		_, _, e := syscall.Syscall(uapi.SYS_KMES_EMIT_BATCH,
			uintptr(unsafe.Pointer(&raw[0])),
			uintptr(len(raw)),
			uintptr(unsafe.Pointer(&emitted)))
		return 0, e
	})
	runtime.KeepAlive(raw)
	runtime.KeepAlive(types)
	runtime.KeepAlive(entries)
	if err != nil {
		if emitted > 0 {
			return fmt.Errorf("libp/event: emit batch: emitted %d event(s) then failed: %w", emitted, err)
		}
		return fmt.Errorf("libp/event: emit batch: %w", err)
	}
	return nil
}

// retry is this package's handle on the shared EINTR-retrying syscall
// helper, libp-go/internal/sys.
var retry = sys.Retry
