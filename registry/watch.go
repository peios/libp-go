package registry

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/peios/libp-go/errno"
	uapi "github.com/peios/pkm/uapi/go"
)

// Change watches. Arming a key fd with Watch turns it into a change-event
// source (PSD-005 §4): the fd becomes pollable (EPOLLIN) and a read
// returns one or more structured event records. Unlike KMES this is a
// plain pollable fd, not an mmap ring. ReadEvents does a blocking read and
// parses the records; for non-blocking / multiplexed use, poll the fd
// (Key.FD) for EPOLLIN first, then read.

// watchReadBuf is the read buffer for one ReadEvents call. It is sized to
// hold many typical (tiny) events, or a large subtree-event burst, in a
// single read.
const watchReadBuf = 64 * 1024

// WatchFilter selects which change categories a watch delivers. Combine
// with bitwise OR. KeyDeleted and Overflow events are always delivered
// regardless of filter.
type WatchFilter uint32

const (
	WatchValue  WatchFilter = uapi.REG_NOTIFY_VALUE  // value writes and deletes on the key
	WatchSubkey WatchFilter = uapi.REG_NOTIFY_SUBKEY // child-key creation and deletion
	WatchSD     WatchFilter = uapi.REG_NOTIFY_SD     // security-descriptor changes
	WatchAll    WatchFilter = uapi.REG_NOTIFY_ALL    // all of the above
)

// WatchEventType is the kind of change a WatchEvent reports.
type WatchEventType uint16

const (
	EventValueSet      WatchEventType = uapi.REG_WATCH_VALUE_SET      // a value was written
	EventValueDeleted  WatchEventType = uapi.REG_WATCH_VALUE_DELETED  // a value was deleted
	EventSubkeyCreated WatchEventType = uapi.REG_WATCH_SUBKEY_CREATED // a child key was created
	EventSubkeyDeleted WatchEventType = uapi.REG_WATCH_SUBKEY_DELETED // a child key was deleted
	EventSDChanged     WatchEventType = uapi.REG_WATCH_SD_CHANGED     // the key's SD changed
	EventKeyDeleted    WatchEventType = uapi.REG_WATCH_KEY_DELETED    // the watched key was deleted/hidden (always delivered)
	EventOverflow      WatchEventType = uapi.REG_WATCH_OVERFLOW       // events were dropped; resync (always delivered)
)

// String names the event type, or its numeric form for an unrecognised
// code (a kind a future kernel adds).
func (e WatchEventType) String() string {
	switch e {
	case EventValueSet:
		return "ValueSet"
	case EventValueDeleted:
		return "ValueDeleted"
	case EventSubkeyCreated:
		return "SubkeyCreated"
	case EventSubkeyDeleted:
		return "SubkeyDeleted"
	case EventSDChanged:
		return "SDChanged"
	case EventKeyDeleted:
		return "KeyDeleted"
	case EventOverflow:
		return "Overflow"
	default:
		return fmt.Sprintf("WatchEventType(%d)", uint16(e))
	}
}

// WatchEvent is one change event delivered to a watch.
type WatchEvent struct {
	// Type is what changed.
	Type WatchEventType
	// Name is the changed entity's name (value or child-key name); empty
	// for whole-key events like KeyDeleted / Overflow.
	Name string
	// Path, for a subtree watch, holds the path components from the watched
	// key down to the changed key. Empty for a direct (on-the-watched-key)
	// change.
	Path []string
}

// Watch arms (or re-arms) a change watch on this key (requires Notify
// access). filter selects which categories to receive; subtree extends the
// watch to descendants. Re-arming replaces the previous settings; an empty
// filter disarms (see Disarm).
func (k *Key) Watch(filter WatchFilter, subtree bool) error {
	args := uapi.Reg_notify_args{
		Filter:  uint32(filter),
		Subtree: boolU8(subtree),
	}
	if err := k.ioctl(uapi.REG_IOC_NOTIFY, ptr(&args)); err != nil {
		return fmt.Errorf("libp/registry: watch: %w", err)
	}
	return nil
}

// Disarm disarms the watch: pending events are discarded and no more are
// queued.
func (k *Key) Disarm() error {
	return k.Watch(0, false)
}

// ReadEvents blocks until at least one watch event is available, then
// returns every record the kernel delivered in that read.
//
// It deliberately does NOT retry on EINTR — a signal cancels the wait and
// surfaces as errno.EINTR, so a caller can interrupt a blocking watcher
// with a signal. For non-blocking use, poll the fd (Key.FD) for EPOLLIN
// first.
func (k *Key) ReadEvents() ([]WatchEvent, error) {
	buf := make([]byte, watchReadBuf)
	// No EINTR retry: the event-wait path opts out (peios-rs design §6).
	r, _, e := syscall.Syscall(syscall.SYS_READ,
		uintptr(k.fd), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	runtime.KeepAlive(buf)
	if e != 0 {
		return nil, fmt.Errorf("libp/registry: read events: %w", errno.Errno(e))
	}
	return parseEvents(buf[:int(r)]), nil
}

// parseEvents parses a read() buffer into events. Each record is
// [total_len u32][type u16][name_len u16][name], optionally followed by a
// subtree path [depth u16]([clen u16][component])*.
func parseEvents(buf []byte) []WatchEvent {
	var out []WatchEvent
	off := 0
	for off+uapi.REG_WATCH_EVENT_MIN_SIZE <= len(buf) {
		totalLen := int(binary.LittleEndian.Uint32(buf[off+uapi.REG_WATCH_EVENT_TOTAL_LEN_OFFSET:]))
		if totalLen < uapi.REG_WATCH_EVENT_MIN_SIZE || off+totalLen > len(buf) {
			break
		}
		rec := buf[off : off+totalLen]
		ev := WatchEvent{
			Type: WatchEventType(binary.LittleEndian.Uint16(rec[uapi.REG_WATCH_EVENT_TYPE_OFFSET:])),
		}
		nameLen := int(binary.LittleEndian.Uint16(rec[uapi.REG_WATCH_EVENT_NAME_LEN_OFFSET:]))
		p := uapi.REG_WATCH_EVENT_NAME_OFFSET
		if p+nameLen <= len(rec) {
			ev.Name = string(rec[p : p+nameLen])
			p += nameLen
		}
		// A subtree event appends a path after the name; a direct event
		// ends at the name (distinguished by whether bytes remain).
		if p+uapi.REG_WATCH_SUBTREE_PATH_DEPTH_SIZE <= len(rec) {
			depth := int(binary.LittleEndian.Uint16(rec[p:]))
			p += uapi.REG_WATCH_SUBTREE_PATH_DEPTH_SIZE
			for range depth {
				if p+uapi.REG_WATCH_PATH_COMPONENT_LEN_SIZE > len(rec) {
					break
				}
				clen := int(binary.LittleEndian.Uint16(rec[p:]))
				p += uapi.REG_WATCH_PATH_COMPONENT_LEN_SIZE
				if p+clen > len(rec) {
					break
				}
				ev.Path = append(ev.Path, string(rec[p:p+clen]))
				p += clen
			}
		}
		out = append(out, ev)
		off += totalLen
	}
	return out
}
