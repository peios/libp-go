// Package event is the libp interface to KMES — the Kernel-Mediated
// Event Stream. It covers both halves of the ABI: emitting events
// (Emit / EmitBatch) and consuming them from the per-CPU ring buffers
// (Ring).
//
// Borrowed vs owned: Ring.Next yields an Event whose EventType and
// Payload alias the ring's mapped memory — valid only until the next
// drain step. To keep an event past that, or to hand it to another
// goroutine, copy it to an OwnedEvent (Ring.Read returns one directly).
//
// It is a libp-tier package — an idiomatic Go surface over the generated
// uapi binding. See libp-design.md and libp-map.md.
package event

import (
	"github.com/peios/libp-go/wire"
	uapi "github.com/peios/pkm/uapi/go"
)

// Event is a KMES event borrowed directly from a ring buffer — an alias
// for wire.Event. Its EventType and Payload slices point into the ring;
// see the package doc on borrowed vs owned events.
type Event = wire.Event

// Origin is the subsystem a KMES event came from (its origin class).
type Origin uint8

const (
	OriginUserspace Origin = uapi.KMES_ORIGIN_USERSPACE
	OriginKMES      Origin = uapi.KMES_ORIGIN_KMES
	OriginKACS      Origin = uapi.KMES_ORIGIN_KACS
	OriginLCS       Origin = uapi.KMES_ORIGIN_LCS
)

// String names the origin class, or "????" for one this build does not
// recognise.
func (o Origin) String() string {
	switch o {
	case OriginUserspace:
		return "USER"
	case OriginKMES:
		return "KMES"
	case OriginKACS:
		return "KACS"
	case OriginLCS:
		return "LCS"
	default:
		return "????"
	}
}

// OwnedEvent is a KMES event copied out of a ring buffer into owned
// memory. Unlike Event it has no tie to the ring's mapping, so it
// survives cursor advances and can be handed to another goroutine.
type OwnedEvent struct {
	EventSize          uint32
	HeaderSize         uint32
	TimestampNS        uint64
	Sequence           uint64
	CPUID              uint16
	Origin             Origin
	EffectiveTokenGUID []byte
	TrueTokenGUID      []byte
	ProcessGUID        []byte
	EventType          []byte
	Payload            []byte
}

// EventTypeString returns the event-type tag as a string.
func (e OwnedEvent) EventTypeString() string { return string(e.EventType) }

// ownedFrom copies a borrowed Event into an OwnedEvent.
func ownedFrom(e Event) OwnedEvent {
	return OwnedEvent{
		EventSize:          e.EventSize,
		HeaderSize:         e.HeaderSize,
		TimestampNS:        e.TimestampNS,
		Sequence:           e.Sequence,
		CPUID:              e.CPUID,
		Origin:             Origin(e.Origin),
		EffectiveTokenGUID: append([]byte(nil), e.EffectiveTokenGUID...),
		TrueTokenGUID:      append([]byte(nil), e.TrueTokenGUID...),
		ProcessGUID:        append([]byte(nil), e.ProcessGUID...),
		EventType:          append([]byte(nil), e.EventType...),
		Payload:            append([]byte(nil), e.Payload...),
	}
}
