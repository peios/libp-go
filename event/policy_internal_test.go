package event

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/peios/libp-go/errno"
	"github.com/peios/libp-go/registry"
	uapi "github.com/peios/pkm/uapi/go"
)

// fakeTree is an in-memory policy tree: key path ("" for Events,
// `kacs\audit` beneath it) to its Enabled value, if any.
type fakeTree struct {
	noRoot bool
	keys   map[string]*registry.Value
	reads  int
	open   int
}

func newTree() *fakeTree { return &fakeTree{keys: map[string]*registry.Value{"": nil}} }

func (t *fakeTree) key(path string, v *registry.Value) *fakeTree {
	acc := ""
	for _, seg := range strings.Split(path, `\`) {
		if acc != "" {
			acc += `\`
		}
		acc += seg
		if _, ok := t.keys[acc]; !ok {
			t.keys[acc] = nil
		}
	}
	t.keys[path] = v
	return t
}

func dword(n uint32) *registry.Value       { v := registry.DWORD(n); return &v }
func val(v registry.Value) *registry.Value { return &v }

func (t *fakeTree) root() policyKey {
	if t.noRoot {
		return nil
	}
	t.open++
	return ""
}

func (t *fakeTree) child(parent policyKey, seg string) policyKey {
	p := parent.(string)
	if p != "" {
		p += `\`
	}
	p += seg
	if _, ok := t.keys[p]; !ok {
		return nil
	}
	t.open++
	return p
}

func (t *fakeTree) enabled(key policyKey) setting {
	t.reads++
	v := t.keys[key.(string)]
	if v == nil {
		return unset
	}
	return interpretEnabled(*v)
}

func (t *fakeTree) release(policyKey) { t.open-- }

func isOn(t *fakeTree, typ string, tier Tier) bool {
	if tier == TierEssential {
		return true
	}
	segs, ok := policySegments(typ)
	if !ok {
		panic(typ)
	}
	return decide(tier, resolve(t, segs))
}

func TestPolicyEmptyTreeUsesTierDefaults(t *testing.T) {
	tr := newTree()
	for tier, want := range map[Tier]bool{TierStandard: true, TierVerbose: false, TierDebug: false, TierEssential: true} {
		if got := isOn(tr, "kacs.token.created", tier); got != want {
			t.Errorf("%v: got %v, want %v", tier, got, want)
		}
	}
	tr = newTree().key("", dword(0))
	tr.noRoot = true
	if !isOn(tr, "a.b.c", TierStandard) || isOn(tr, "a.b.c", TierVerbose) {
		t.Error("absent root must decide by tier")
	}
}

// The PGSS §6.9 example table.
func TestPolicySpecExample(t *testing.T) {
	tr := newTree().key("kacs", dword(0)).key(`kacs\audit`, dword(1))
	cases := []struct {
		typ  string
		tier Tier
		want bool
	}{
		{"lcs.config.value.rejected", TierStandard, true},
		{"kacs.caap.staging.diverged", TierStandard, false},
		{"kacs.audit.handle.used", TierStandard, true},
		{"kacs.audit.access.checked", TierEssential, true},
		{"lcs.config.value.rejected", TierVerbose, false},
		{"kacs.audit.handle.used", TierVerbose, true},
	}
	for _, c := range cases {
		if got := isOn(tr, c.typ, c.tier); got != c.want {
			t.Errorf("%s/%v: got %v, want %v", c.typ, c.tier, got, c.want)
		}
	}
	tr.key("", dword(0))
	if isOn(tr, "lcs.config.value.rejected", TierStandard) {
		t.Error("Events=0 must switch lcs off")
	}
	if !isOn(tr, "kacs.audit.handle.used", TierStandard) {
		t.Error("kacs\\audit=1 must still win")
	}
}

func TestPolicyDeepestWinsBothWays(t *testing.T) {
	tr := newTree().key("", dword(0)).key("a", dword(1)).key(`a\b`, dword(0)).key(`a\b\c`, dword(1))
	for typ, want := range map[string]bool{"a.b.c": true, "a.b.d": false, "a.x.y": true, "z.y.x": false} {
		if got := isOn(tr, typ, TierStandard); got != want {
			t.Errorf("%s: got %v, want %v", typ, got, want)
		}
	}
}

func TestPolicyTypesOwnKeyCountsAndWalkStops(t *testing.T) {
	tr := newTree().key(`a\b\c`, dword(1)).key(`a\b\c\d`, dword(0))
	if !isOn(tr, "a.b.c", TierDebug) {
		t.Error("the type's own key must count")
	}
	if tr.reads != 4 {
		t.Errorf("read %d keys, want 4 (Events, a, a\\b, a\\b\\c)", tr.reads)
	}
	if tr.open != 0 {
		t.Errorf("%d keys left open", tr.open)
	}
	if isOn(tr, "a.b.cc", TierDebug) {
		t.Error("a sibling must not inherit")
	}
}

func TestPolicyMissingKeyKeepsWhatWasFound(t *testing.T) {
	if !isOn(newTree().key("a", dword(1)), "a.b.c", TierVerbose) {
		t.Error("a's setting must stand when a\\b is missing")
	}
	if isOn(newTree().key("a", dword(0)).key(`a\b`, nil), "a.b.c", TierStandard) {
		t.Error("a key without a value must not reset")
	}
}

func TestPolicyPackageRootSplits(t *testing.T) {
	tr := newTree().key(`org\jellyfin`, dword(0)).key(`org\jellyfin\server\playback`, dword(1))
	if isOn(tr, "org.jellyfin.server.library.scanned", TierStandard) {
		t.Error("org\\jellyfin=0 must cover the package")
	}
	if !isOn(tr, "org.jellyfin.server.playback.started", TierVerbose) {
		t.Error("the deeper key must win")
	}
	if !isOn(tr, "org.other.app.thing.done", TierStandard) {
		t.Error("another package must be untouched")
	}
}

func TestPolicyMalformedValuesIgnored(t *testing.T) {
	bad := []registry.Value{
		registry.DWORD(2), registry.DWORD(0xFFFFFFFF), registry.SZ("1"),
		registry.QWORD(1), registry.DWORDBigEndian(1), registry.Binary([]byte{1, 0, 0, 0}),
	}
	for _, v := range bad {
		if isOn(newTree().key("a", dword(0)).key(`a\b`, val(v)), "a.b.c", TierStandard) {
			t.Errorf("%v must be ignored (keeping off)", v.Kind())
		}
		if !isOn(newTree().key("a", dword(1)).key(`a\b`, val(v)), "a.b.c", TierVerbose) {
			t.Errorf("%v must be ignored (keeping on)", v.Kind())
		}
	}
}

func TestPolicySegments(t *testing.T) {
	good := []string{"a.b.c", "single", "org.c++.app.thing.done"}
	bad := []string{"", "a..b", ".a", "a.", `a.b\c.d`, "a.b/c.d", "a.b\x00.d", "a.\xff.d"}
	for _, s := range good {
		if _, ok := policySegments(s); !ok {
			t.Errorf("%q rejected", s)
		}
	}
	for _, s := range bad {
		if _, ok := policySegments(s); ok {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestPolicyRejectsBadArguments(t *testing.T) {
	p := OpenPolicy()
	defer p.Close()
	if _, err := p.Enabled("a..b", TierEssential); !errors.Is(err, errno.EINVAL) {
		t.Errorf("malformed type: %v", err)
	}
	if _, err := p.Enabled("a.b.c", Tier(9)); !errors.Is(err, errno.EINVAL) {
		t.Errorf("unknown tier: %v", err)
	}
}

// Off a Peios kernel nothing can be read: the policy decides by tier, as
// PGSS §6.9 requires of an emitter with no readable policy. On a Peios
// kernel the default tree sets nothing under a.b.c, with the same result.
func TestPolicyWithoutARegistryDecidesByTier(t *testing.T) {
	p := OpenPolicy()
	defer p.Close()
	for tier, want := range map[Tier]bool{TierEssential: true, TierStandard: true, TierVerbose: false, TierDebug: false} {
		got, err := p.Enabled("pei1281.test.unset.type", tier)
		if err != nil || got != want {
			t.Errorf("%v: got %v, %v; want %v", tier, got, err, want)
		}
	}
	if ok, err := p.EmitWith("pei1281.test.unset.type", TierDebug, func() ([]byte, error) {
		t.Fatal("built a payload for a type that is off")
		return nil, nil
	}); ok || err != nil {
		t.Errorf("EmitWith: %v, %v", ok, err)
	}
	p.Close()
	if ok, _ := p.Enabled("a.b.c", TierStandard); !ok {
		t.Error("a closed policy must still decide by tier")
	}
}

func record(typ uint16, name string, path []string, withPath bool) []byte {
	r := make([]byte, 8, 64)
	binary.LittleEndian.PutUint16(r[4:], typ)
	binary.LittleEndian.PutUint16(r[6:], uint16(len(name)))
	r = append(r, name...)
	if withPath {
		r = binary.LittleEndian.AppendUint16(r, uint16(len(path)))
		for _, c := range path {
			r = binary.LittleEndian.AppendUint16(r, uint16(len(c)))
			r = append(r, c...)
		}
	}
	binary.LittleEndian.PutUint32(r, uint32(len(r)))
	return r
}

func TestClassifyRecords(t *testing.T) {
	buf := append(record(uapi.REG_WATCH_VALUE_SET, "Enabled", []string{"kacs"}, true),
		record(uapi.REG_WATCH_SUBKEY_CREATED, "audit", nil, true)...)
	if n := classifyRecords(buf); !n.changed || n.gone {
		t.Errorf("value+subkey: %+v", n)
	}
	if n := classifyRecords(nil); n.changed || n.gone {
		t.Errorf("empty: %+v", n)
	}
	if n := classifyRecords(record(uapi.REG_WATCH_OVERFLOW, "", nil, false)); !n.changed || n.gone {
		t.Errorf("overflow: %+v", n)
	}
	if n := classifyRecords(record(uapi.REG_WATCH_KEY_DELETED, "", nil, false)); !n.gone {
		t.Errorf("bare key-deleted: %+v", n)
	}
	if n := classifyRecords(record(uapi.REG_WATCH_KEY_DELETED, "", nil, true)); !n.gone {
		t.Errorf("own key-deleted: %+v", n)
	}
	if n := classifyRecords(record(uapi.REG_WATCH_KEY_DELETED, "", []string{"kacs"}, true)); n.gone || !n.changed {
		t.Errorf("descendant key-deleted: %+v", n)
	}
	if n := classifyRecords([]byte{1, 2, 3}); !n.gone {
		t.Errorf("short: %+v", n)
	}
	r := record(uapi.REG_WATCH_VALUE_SET, "x", nil, false)
	binary.LittleEndian.PutUint32(r, 1000)
	if n := classifyRecords(r); !n.gone {
		t.Errorf("overlong total_len: %+v", n)
	}
}
