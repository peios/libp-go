package layers_test

import (
	"errors"
	"testing"

	"github.com/peios/libp-go/registry"
	"github.com/peios/libp-go/registry/layers"
)

// The reserved-base-layer guards reject client-side, before any syscall,
// so they are exercisable off a Peios kernel. Every mutating entry point
// must refuse the base layer (case-insensitively) with ErrReservedLayer.
func TestBaseLayerIsReserved(t *testing.T) {
	for _, name := range []string{"base", "BASE", "Base"} {
		t.Run(name, func(t *testing.T) {
			if _, err := layers.Create(name).Call(); !errors.Is(err, registry.ErrReservedLayer) {
				t.Errorf("Create(%q): want ErrReservedLayer, got %v", name, err)
			}
			if err := layers.SetPrecedence(name, 5); !errors.Is(err, registry.ErrReservedLayer) {
				t.Errorf("SetPrecedence(%q): want ErrReservedLayer, got %v", name, err)
			}
			if err := layers.SetEnabled(name, false); !errors.Is(err, registry.ErrReservedLayer) {
				t.Errorf("SetEnabled(%q): want ErrReservedLayer, got %v", name, err)
			}
			if err := layers.Delete(name); !errors.Is(err, registry.ErrReservedLayer) {
				t.Errorf("Delete(%q): want ErrReservedLayer, got %v", name, err)
			}
		})
	}
}
