package wire

import (
	"encoding/binary"
	"errors"

	uapi "github.com/peios/pkm/uapi/go"
)

// KMES event-header field offsets within the fixed base, and the base
// size (the offset at which the event-type string begins).
const (
	evSizeOff      = uapi.KMES_EVENT_SIZE_OFFSET
	evHeaderOff    = uapi.KMES_EVENT_HEADER_SIZE_OFFSET
	evTimestampOff = uapi.KMES_EVENT_TIMESTAMP_NS_OFFSET
	evSequenceOff  = uapi.KMES_EVENT_SEQUENCE_OFFSET
	evCPUIDOff     = uapi.KMES_EVENT_CPU_ID_OFFSET
	evOriginOff    = uapi.KMES_EVENT_ORIGIN_CLASS_OFFSET

	evEffectiveTokenGUIDOff = uapi.KMES_EVENT_EFFECTIVE_TOKEN_GUID_OFFSET
	evTrueTokenGUIDOff      = uapi.KMES_EVENT_TRUE_TOKEN_GUID_OFFSET
	evProcessGUIDOff        = uapi.KMES_EVENT_PROCESS_GUID_OFFSET
	evGUIDSize              = uapi.KMES_EVENT_GUID_SIZE

	evTypeLenOff = uapi.KMES_EVENT_TYPE_LEN_OFFSET
	evHeaderBase = uapi.KMES_EVENT_HEADER_BASE_SIZE
)

// ErrBadEvent reports a buffer that is not a well-formed KMES event.
var ErrBadEvent = errors.New("libp/wire: malformed KMES event")

// Event is a parsed KMES event: the on-wire header fields plus the
// event-type string and payload.
//
// EventType and Payload are slices into the buffer ParseEvent was given.
// When that buffer is a live ring-buffer mapping (event.Ring.Next), the
// slices are valid only until the ring's read cursor advances — copy
// them out to keep an event longer.
type Event struct {
	// EventSize is the total event length in bytes (header + payload).
	EventSize uint32
	// HeaderSize is the byte offset from the event start to the payload.
	HeaderSize uint32
	// TimestampNS is the wall-clock emission time (ns since the epoch).
	TimestampNS uint64
	// Sequence is the per-CPU, per-boot monotonic sequence number.
	Sequence uint64
	// CPUID is the CPU the event was emitted on.
	CPUID uint16
	// Origin is the raw origin-class byte (a KMES_ORIGIN_* value).
	Origin uint8
	// EffectiveTokenGUID is the 16-byte GUID of the effective token at
	// emission time. The null GUID (all zero) means identity was
	// unavailable (KACS not initialised or no process context).
	EffectiveTokenGUID []byte
	// TrueTokenGUID is the 16-byte GUID of the process's primary token.
	TrueTokenGUID []byte
	// ProcessGUID is the 16-byte GUID of the emitting process (assigned at
	// fork).
	ProcessGUID []byte
	// EventType is the event-type tag (UTF-8, not NUL-terminated).
	EventType []byte
	// Payload is the msgpack-encoded payload.
	Payload []byte
}

// ParseEvent decodes one KMES event laid out at the start of buf. The
// returned EventType and Payload slices alias buf. It returns ErrBadEvent
// if buf does not begin with a structurally valid event.
//
// The payload is located via HeaderSize, not the end of the type string,
// so a future header revision may insert reserved bytes between them
// without breaking consumers.
func ParseEvent(buf []byte) (Event, error) {
	if len(buf) < evHeaderBase {
		return Event{}, ErrBadEvent
	}
	eventSize := binary.LittleEndian.Uint32(buf[evSizeOff:])
	headerSize := binary.LittleEndian.Uint32(buf[evHeaderOff:])
	etlen := int(binary.LittleEndian.Uint16(buf[evTypeLenOff:]))

	total := int(eventSize)
	hdr := int(headerSize)
	typeEnd := evHeaderBase + etlen
	if total < evHeaderBase || total > len(buf) ||
		hdr < evHeaderBase || hdr > total || typeEnd > hdr {
		return Event{}, ErrBadEvent
	}
	return Event{
		EventSize:   eventSize,
		HeaderSize:  headerSize,
		TimestampNS: binary.LittleEndian.Uint64(buf[evTimestampOff:]),
		Sequence:    binary.LittleEndian.Uint64(buf[evSequenceOff:]),
		CPUID:       binary.LittleEndian.Uint16(buf[evCPUIDOff:]),
		Origin:      buf[evOriginOff],
		// GUID ranges sit within evHeaderBase, already bounds-checked above.
		EffectiveTokenGUID: buf[evEffectiveTokenGUIDOff : evEffectiveTokenGUIDOff+evGUIDSize],
		TrueTokenGUID:      buf[evTrueTokenGUIDOff : evTrueTokenGUIDOff+evGUIDSize],
		ProcessGUID:        buf[evProcessGUIDOff : evProcessGUIDOff+evGUIDSize],
		EventType:          buf[evHeaderBase:typeEnd],
		Payload:            buf[hdr:total],
	}, nil
}
