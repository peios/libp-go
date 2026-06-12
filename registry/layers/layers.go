// Package layers is libp-registry's first-class layer management.
//
// A layer is a named, precedence-ordered overlay of registry writes — the
// mechanism behind role management, Group Policy, and configuration revert
// (PSD-005 §2.6). LCS has no dedicated layer syscall: a layer *is* a key
// at `Machine\System\Registry\Layers\<name>\` carrying Precedence and
// Enabled values. Hand-writing that subtree is an anti-pattern — it is
// easy to leave a half-formed layer live, to forget the base-layer
// protection, or to trip the precedence privilege check with a cryptic
// error. This package owns the path, the value schema, the atomic create,
// and the guards so nothing else ever touches it directly.
package layers

import (
	"fmt"
	"strings"

	"github.com/peios/libp-go/registry"
	"github.com/peios/libp-go/wire"
)

// layersRoot is the well-known key under which all layer metadata lives;
// baseLayer is the reserved base layer that always exists and cannot be
// deleted, disabled, or re-precedenced.
const (
	layersRoot = `Machine\System\Registry\Layers`
	baseLayer  = "base"
)

// Info is a snapshot of a layer's metadata. From Get / List / Builder.Call.
type Info struct {
	// Name is the layer name.
	Name string
	// Precedence: higher overrides lower. 0 is the role tier; > 0 is the
	// Group Policy tier and requires SeTcbPrivilege to set.
	Precedence uint32
	// Enabled reports whether the layer participates in resolution.
	Enabled bool
	// Owner is the creator's SID, if the layer records one (informational).
	// Owner.IsValid() is false when no owner is recorded.
	Owner wire.SID
}

func layerPath(name string) string { return layersRoot + `\` + name }

// guardReserved rejects an operation on the reserved base layer
// client-side, before contacting the kernel.
func guardReserved(name, verb string) error {
	if strings.EqualFold(name, baseLayer) {
		return fmt.Errorf("libp/registry/layers: the base layer cannot be %s: %w",
			verb, registry.ErrReservedLayer)
	}
	return nil
}

// Builder is a fluent builder for a new layer. Precedence defaults to 0
// (the role tier), enabled to true; the owner is recorded by the kernel as
// the caller.
type Builder struct {
	name       string
	precedence uint32
	enabled    bool
}

// Create starts creating a layer. Configure with the builder, then Call.
func Create(name string) *Builder {
	return &Builder{name: name, precedence: 0, enabled: true}
}

// Precedence sets the layer's precedence (default 0). Values > 0 require
// SeTcbPrivilege.
func (b *Builder) Precedence(precedence uint32) *Builder {
	b.precedence = precedence
	return b
}

// Enabled sets whether the layer is enabled (default true).
func (b *Builder) Enabled(enabled bool) *Builder {
	b.enabled = enabled
	return b
}

// Disabled creates the layer disabled.
func (b *Builder) Disabled() *Builder {
	b.enabled = false
	return b
}

// Call creates the layer. The metadata key and its Precedence/Enabled
// values are written in a single transaction, so the layer never goes live
// half-formed.
func (b *Builder) Call() (Info, error) {
	if err := guardReserved(b.name, "created"); err != nil {
		return Info{}, err
	}
	path := layerPath(b.name)
	err := registry.Transact(func(tx *registry.Txn) error {
		key, _, err := tx.Create(path).Access(registry.AllAccess).Call()
		if err != nil {
			return err
		}
		defer key.Close()
		w := tx.At(key)
		if err := w.Base().SetValue("Precedence", registry.DWORD(b.precedence)); err != nil {
			return err
		}
		return w.Base().SetValue("Enabled", registry.DWORD(boolUint32(b.enabled)))
	})
	if err != nil {
		return Info{}, err
	}
	return Info{Name: b.name, Precedence: b.precedence, Enabled: b.enabled}, nil
}

// Get reads a layer's metadata.
func Get(name string) (Info, error) {
	key, err := registry.Open(layerPath(name), registry.QueryValue|registry.ReadControl)
	if err != nil {
		return Info{}, err
	}
	defer key.Close()

	info := Info{Name: name, Enabled: true} // absent Enabled defaults to enabled

	if v, found, err := key.TryQueryValue("Precedence"); err != nil {
		return Info{}, err
	} else if found {
		if n, ok := v.Uint32(); ok {
			info.Precedence = n
		}
	}
	if v, found, err := key.TryQueryValue("Enabled"); err != nil {
		return Info{}, err
	} else if found {
		if n, ok := v.Uint32(); ok {
			info.Enabled = n != 0
		}
	}
	if v, found, err := key.TryQueryValue("Owner"); err != nil {
		return Info{}, err
	} else if found {
		if b, ok := v.Bytes(); ok {
			if sid, err := wire.ParseSID(b); err == nil {
				info.Owner = sid
			}
		}
	}
	return info, nil
}

// List returns every layer (base included), each with its metadata.
func List() ([]Info, error) {
	root, err := registry.Open(layersRoot, registry.EnumerateSubKeys)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	subs, err := root.Subkeys()
	if err != nil {
		return nil, err
	}
	out := make([]Info, 0, len(subs))
	for _, sub := range subs {
		info, err := Get(sub.Name)
		if err != nil {
			return nil, err
		}
		out = append(out, info)
	}
	return out, nil
}

// SetPrecedence sets a layer's precedence. It rejects the reserved base
// layer client-side; values > 0 require SeTcbPrivilege (surfaced as EPERM).
func SetPrecedence(name string, precedence uint32) error {
	if err := guardReserved(name, "re-precedenced"); err != nil {
		return err
	}
	key, err := registry.Open(layerPath(name), registry.SetValue)
	if err != nil {
		return err
	}
	defer key.Close()
	return key.Base().SetValue("Precedence", registry.DWORD(precedence))
}

// SetEnabled enables or disables a layer. It rejects the reserved base
// layer client-side.
func SetEnabled(name string, enabled bool) error {
	if err := guardReserved(name, "enabled or disabled"); err != nil {
		return err
	}
	key, err := registry.Open(layerPath(name), registry.SetValue)
	if err != nil {
		return err
	}
	defer key.Close()
	return key.Base().SetValue("Enabled", registry.DWORD(boolUint32(enabled)))
}

// Delete deletes a layer: it removes the metadata key, and the kernel
// reverts every write the layer carried. It rejects the reserved base
// layer client-side.
func Delete(name string) error {
	if err := guardReserved(name, "deleted"); err != nil {
		return err
	}
	key, err := registry.Open(layerPath(name), registry.Delete)
	if err != nil {
		return err
	}
	defer key.Close()
	return key.Base().DeleteKey()
}

func boolUint32(b bool) uint32 {
	if b {
		return 1
	}
	return 0
}
