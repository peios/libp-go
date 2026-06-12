package registry_test

import (
	"testing"

	"github.com/peios/libp-go/registry"
)

func TestSpecificRightsMatchPSD005(t *testing.T) {
	cases := []struct {
		got  registry.Access
		want uint32
	}{
		{registry.QueryValue, 0x0001},
		{registry.SetValue, 0x0002},
		{registry.CreateSubKey, 0x0004},
		{registry.EnumerateSubKeys, 0x0008},
		{registry.Notify, 0x0010},
		{registry.CreateLink, 0x0020},
	}
	for _, c := range cases {
		if uint32(c.got) != c.want {
			t.Errorf("access %v: got %#x, want %#x", c.got, uint32(c.got), c.want)
		}
	}
}

func TestConvenienceMasksComposeSpecificAndStandardRights(t *testing.T) {
	wantRead := registry.QueryValue | registry.EnumerateSubKeys | registry.Notify | registry.ReadControl
	if registry.Read != wantRead {
		t.Errorf("Read = %#x, want %#x", uint32(registry.Read), uint32(wantRead))
	}
	wantWrite := registry.SetValue | registry.CreateSubKey | registry.ReadControl
	if registry.Write != wantWrite {
		t.Errorf("Write = %#x, want %#x", uint32(registry.Write), uint32(wantWrite))
	}
}

func TestContains(t *testing.T) {
	a := registry.QueryValue | registry.SetValue
	if !a.Contains(registry.QueryValue) {
		t.Error("a should contain QueryValue")
	}
	if !a.Contains(registry.SetValue) {
		t.Error("a should contain SetValue")
	}
	if a.Contains(registry.Delete) {
		t.Error("a should not contain Delete")
	}
}
