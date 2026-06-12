package registry_test

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"github.com/peios/libp-go/registry"
)

// roundtrip encodes a value and decodes the result back.
func roundtrip(t *testing.T, v registry.Value) registry.Value {
	t.Helper()
	ty, data := v.Encode()
	got, err := registry.Decode(ty, data)
	if err != nil {
		t.Fatalf("Decode after Encode of %v: %v", v, err)
	}
	return got
}

func TestIntegersRoundtrip(t *testing.T) {
	d := roundtrip(t, registry.DWORD(0xDEADBEEF))
	if n, ok := d.Uint32(); !ok || n != 0xDEADBEEF {
		t.Fatalf("DWORD roundtrip: got %v (%d, %v)", d, n, ok)
	}
	q := roundtrip(t, registry.QWORD(0x0123456789ABCDEF))
	if n, ok := q.Uint64(); !ok || n != 0x0123456789ABCDEF {
		t.Fatalf("QWORD roundtrip: got %v (%d, %v)", q, n, ok)
	}

	// DWORD is stored little-endian, DWORD_BIG_ENDIAN big-endian.
	if _, b := registry.DWORD(1).Encode(); !bytes.Equal(b, []byte{1, 0, 0, 0}) {
		t.Fatalf("DWORD(1) encodes to %v, want little-endian", b)
	}
	if _, b := registry.DWORDBigEndian(1).Encode(); !bytes.Equal(b, []byte{0, 0, 0, 1}) {
		t.Fatalf("DWORDBigEndian(1) encodes to %v, want big-endian", b)
	}
}

func TestStringsRoundtripUTF8NULTerminated(t *testing.T) {
	if _, b := registry.SZ("hi").Encode(); !bytes.Equal(b, []byte("hi\x00")) {
		t.Fatalf("SZ(\"hi\") encodes to %v, want UTF-8 NUL-terminated", b)
	}
	for _, s := range []string{"héllo", "", "tab\tand\nnewline"} {
		got := roundtrip(t, registry.SZ(s))
		if v, ok := got.Str(); !ok || v != s {
			t.Fatalf("SZ(%q) roundtrip: got %q (%v)", s, v, ok)
		}
	}
}

func TestMultiSZRoundtrips(t *testing.T) {
	v := registry.MultiSZ([]string{"a", "bb", "ccc"})
	got := roundtrip(t, v)
	if list, ok := got.List(); !ok || !reflect.DeepEqual(list, []string{"a", "bb", "ccc"}) {
		t.Fatalf("MultiSZ roundtrip: got %v (%v)", list, ok)
	}
	// Encoding is each-string-then-NUL plus a final NUL.
	if _, b := registry.MultiSZ([]string{"a"}).Encode(); !bytes.Equal(b, []byte("a\x00\x00")) {
		t.Fatalf("MultiSZ([a]) encodes to %v, want a\\0\\0", b)
	}
	// An empty list roundtrips to an empty (non-nil-semantics) list.
	empty := roundtrip(t, registry.MultiSZ(nil))
	if list, ok := empty.List(); !ok || len(list) != 0 {
		t.Fatalf("MultiSZ(nil) roundtrip: got %v (%v)", list, ok)
	}
}

func TestDecodeRejectsMalformedFixedWidth(t *testing.T) {
	if _, err := registry.Decode(registry.TypeDWORD, []byte{1, 2, 3}); !errors.Is(err, registry.ErrMalformedValue) {
		t.Fatalf("Decode short DWORD: want ErrMalformedValue, got %v", err)
	}
	if _, err := registry.Decode(registry.TypeQWORD, []byte{1, 2, 3, 4}); !errors.Is(err, registry.ErrMalformedValue) {
		t.Fatalf("Decode short QWORD: want ErrMalformedValue, got %v", err)
	}
	// Invalid UTF-8 in a string type is malformed.
	if _, err := registry.Decode(registry.TypeSZ, []byte{0xFF, 0xFE, 0}); !errors.Is(err, registry.ErrMalformedValue) {
		t.Fatalf("Decode non-UTF-8 SZ: want ErrMalformedValue, got %v", err)
	}
}

func TestUnknownTypePreservedAsOther(t *testing.T) {
	// Type 8 (REG_RESOURCE_LIST) is not one libp models; it must round-trip
	// verbatim through Other.
	const hwType registry.Type = 8
	v, err := registry.Decode(hwType, []byte{9, 9, 9})
	if err != nil {
		t.Fatalf("Decode unknown type: %v", err)
	}
	if v.Kind() != hwType {
		t.Fatalf("Other kind: got %v, want %v", v.Kind(), hwType)
	}
	b, ok := v.Bytes()
	if !ok || !bytes.Equal(b, []byte{9, 9, 9}) {
		t.Fatalf("Other bytes: got %v (%v)", b, ok)
	}
	ty, data := v.Encode()
	if ty != hwType || !bytes.Equal(data, []byte{9, 9, 9}) {
		t.Fatalf("Other re-encode: got (%v, %v)", ty, data)
	}
}

func TestAccessorsRejectWrongType(t *testing.T) {
	if _, ok := registry.SZ("x").Uint32(); ok {
		t.Fatal("Str value should not yield a Uint32")
	}
	if _, ok := registry.DWORD(1).Str(); ok {
		t.Fatal("DWORD value should not yield a Str")
	}
	if _, ok := registry.DWORD(1).Bytes(); ok {
		t.Fatal("a known non-binary type should not yield Bytes")
	}
}
