// Package sddl implements SDDL — the Security Descriptor Definition
// Language, the textual security-descriptor format — for libp. Parse
// turns an SDDL string into an sd.Descriptor; Format renders one back.
//
// SDDL is a userspace convenience, not a kernel capability: nothing in
// KACS speaks SDDL, and a consumer that needs only the binary
// descriptor codec can depend on sd alone. See libp-design.md.
//
// The grammar follows MS-DTYP §2.5.1. Access masks are emitted as hex
// and accepted as hex, decimal, or the standard rights mnemonics.
// Two-letter SID aliases resolve against the MS-DTYP alias table;
// domain- and machine-relative aliases (DA, EA, LA, …) need a
// resolution context — see WithDomain and WithMachine.
//
// Callback (conditional) and resource-attribute ACEs are recognised but
// not yet implemented; Parse and Format reject them with a clear error.
package sddl

import (
	"fmt"
	"strings"

	"github.com/peios/libp-go/sd"
	"github.com/peios/libp-go/wire"
)

// options carries the resolution context for domain- and machine-
// relative SID aliases. The zero value resolves absolute aliases only.
type options struct {
	domain  wire.SID
	machine wire.SID
}

// An Option configures Parse or Format.
type Option func(*options)

// WithDomain supplies the domain SID that domain-relative aliases — DA,
// DU, EA and the rest — resolve against. Without it, a domain-relative
// alias is reported as an error rather than silently dropped.
func WithDomain(sid wire.SID) Option { return func(o *options) { o.domain = sid } }

// WithMachine supplies the local machine SID that machine-relative
// aliases — LA and LG — resolve against.
func WithMachine(sid wire.SID) Option { return func(o *options) { o.machine = sid } }

func collect(opts []Option) options {
	var o options
	for _, fn := range opts {
		fn(&o)
	}
	return o
}

// A SyntaxError reports malformed SDDL: the byte offset into the input
// at which parsing failed, and what went wrong there.
type SyntaxError struct {
	Offset int
	Msg    string
}

func (e *SyntaxError) Error() string {
	return fmt.Sprintf("libp/sddl: offset %d: %s", e.Offset, e.Msg)
}

// Parse decodes an SDDL string into a security descriptor. Any subset
// of the owner (O:), group (G:), DACL (D:) and SACL (S:) components may
// appear; an absent component leaves its Descriptor field zero.
func Parse(s string, opts ...Option) (sd.Descriptor, error) {
	p := &parser{in: strings.TrimSpace(s), opt: collect(opts)}
	return p.parse()
}

// Format renders a security descriptor as an SDDL string. Access masks
// are emitted as hex; a SID is emitted as its alias where one is known
// and as the raw S-1-… form otherwise.
func Format(d sd.Descriptor, opts ...Option) (string, error) {
	return formatDescriptor(d, collect(opts))
}
