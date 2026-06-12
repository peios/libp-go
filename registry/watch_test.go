package registry

import (
	"encoding/binary"
	"reflect"
	"testing"
)

// directEvent builds a direct (non-subtree) watch record:
// [total_len u32][type u16][name_len u16][name].
func directEvent(eventType uint16, name string) []byte {
	total := 8 + len(name)
	b := make([]byte, 0, total)
	b = binary.LittleEndian.AppendUint32(b, uint32(total))
	b = binary.LittleEndian.AppendUint16(b, eventType)
	b = binary.LittleEndian.AppendUint16(b, uint16(len(name)))
	b = append(b, name...)
	return b
}

func TestParsesMultipleDirectEventsInOneRead(t *testing.T) {
	buf := directEvent(uint16(EventValueSet), "Mode")
	buf = append(buf, directEvent(uint16(EventKeyDeleted), "")...) // no name

	events := parseEvents(buf)
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2", len(events))
	}
	if events[0].Type != EventValueSet || events[0].Name != "Mode" || len(events[0].Path) != 0 {
		t.Errorf("event 0 = %+v", events[0])
	}
	if events[1].Type != EventKeyDeleted || events[1].Name != "" {
		t.Errorf("event 1 = %+v", events[1])
	}
}

func TestParsesSubtreePath(t *testing.T) {
	// type=SubkeyCreated, name="X", depth=2, components "a","bb".
	name := "X"
	body := make([]byte, 0)
	body = binary.LittleEndian.AppendUint16(body, uint16(EventSubkeyCreated))
	body = binary.LittleEndian.AppendUint16(body, uint16(len(name)))
	body = append(body, name...)
	body = binary.LittleEndian.AppendUint16(body, 2) // depth
	body = binary.LittleEndian.AppendUint16(body, 1) // len("a")
	body = append(body, "a"...)
	body = binary.LittleEndian.AppendUint16(body, 2) // len("bb")
	body = append(body, "bb"...)

	rec := binary.LittleEndian.AppendUint32(nil, uint32(4+len(body)))
	rec = append(rec, body...)

	events := parseEvents(rec)
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	if events[0].Type != EventSubkeyCreated || events[0].Name != "X" {
		t.Errorf("event = %+v", events[0])
	}
	if !reflect.DeepEqual(events[0].Path, []string{"a", "bb"}) {
		t.Errorf("path = %v, want [a bb]", events[0].Path)
	}
}

func TestTruncatedRecordIsIgnored(t *testing.T) {
	buf := directEvent(uint16(EventValueSet), "ok")
	buf = append(buf, 0xFF, 0xFF) // garbage tail, < min record size

	events := parseEvents(buf)
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	if events[0].Name != "ok" {
		t.Errorf("event name = %q, want ok", events[0].Name)
	}
}
