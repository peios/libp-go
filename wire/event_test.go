package wire_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/peios/libp-go/wire"
)

// buildEvent assembles a synthetic KMES event. gap inserts reserved
// bytes between the type string and the payload, exercising the rule
// that the payload is located via header_size, not the type-string end.
func buildEvent(eventType string, origin uint8, payload []byte, gap int) []byte {
	const hdrBase = 77
	headerSize := hdrBase + len(eventType) + gap
	eventSize := headerSize + len(payload)
	buf := make([]byte, eventSize)
	binary.LittleEndian.PutUint32(buf[0:], uint32(eventSize))
	binary.LittleEndian.PutUint32(buf[4:], uint32(headerSize))
	binary.LittleEndian.PutUint64(buf[8:], 123456789)
	binary.LittleEndian.PutUint64(buf[16:], 42)
	binary.LittleEndian.PutUint16(buf[24:], 3)
	buf[26] = origin
	// Identity GUIDs at offsets 27/43/59 — distinct sentinels so the parse
	// offsets are exercised independently.
	for i := range 16 {
		buf[27+i] = 0x10 | byte(i)
		buf[43+i] = 0x20 | byte(i)
		buf[59+i] = 0x30 | byte(i)
	}
	binary.LittleEndian.PutUint16(buf[75:], uint16(len(eventType)))
	copy(buf[hdrBase:], eventType)
	copy(buf[headerSize:], payload)
	return buf
}

func TestParseEventRoundTrip(t *testing.T) {
	payload := []byte{0x81, 0xa1, 'k', 0x01}
	ev, err := wire.ParseEvent(buildEvent("test.event", 2, payload, 0))
	if err != nil {
		t.Fatalf("ParseEvent: %v", err)
	}
	if ev.TimestampNS != 123456789 || ev.Sequence != 42 || ev.CPUID != 3 || ev.Origin != 2 {
		t.Fatalf("header fields decoded wrong: %+v", ev)
	}
	if string(ev.EventType) != "test.event" {
		t.Fatalf("EventType = %q, want %q", ev.EventType, "test.event")
	}
	if !bytes.Equal(ev.Payload, payload) {
		t.Fatalf("Payload = %x, want %x", ev.Payload, payload)
	}
	if len(ev.EffectiveTokenGUID) != 16 || ev.EffectiveTokenGUID[0] != 0x10 ||
		len(ev.TrueTokenGUID) != 16 || ev.TrueTokenGUID[0] != 0x20 ||
		len(ev.ProcessGUID) != 16 || ev.ProcessGUID[0] != 0x30 {
		t.Fatalf("identity GUIDs decoded wrong: eff=%x true=%x proc=%x",
			ev.EffectiveTokenGUID, ev.TrueTokenGUID, ev.ProcessGUID)
	}
}

// TestParseEventUsesHeaderSize checks the payload is located via
// header_size even when reserved bytes sit after the type string.
func TestParseEventUsesHeaderSize(t *testing.T) {
	payload := []byte{0xc3} // msgpack true
	ev, err := wire.ParseEvent(buildEvent("x", 0, payload, 8))
	if err != nil {
		t.Fatalf("ParseEvent: %v", err)
	}
	if string(ev.EventType) != "x" {
		t.Fatalf("EventType = %q, want %q", ev.EventType, "x")
	}
	if !bytes.Equal(ev.Payload, payload) {
		t.Fatalf("Payload = %x, want %x", ev.Payload, payload)
	}
}

func TestParseEventRejectsMalformed(t *testing.T) {
	// Shorter than the fixed header.
	if _, err := wire.ParseEvent(make([]byte, 10)); !errors.Is(err, wire.ErrBadEvent) {
		t.Errorf("truncated: want ErrBadEvent, got %v", err)
	}
	// header_size declares more bytes than the event holds.
	bad := make([]byte, 77)
	binary.LittleEndian.PutUint32(bad[0:], 77)
	binary.LittleEndian.PutUint32(bad[4:], 77+16)
	if _, err := wire.ParseEvent(bad); !errors.Is(err, wire.ErrBadEvent) {
		t.Errorf("header past event: want ErrBadEvent, got %v", err)
	}
}
