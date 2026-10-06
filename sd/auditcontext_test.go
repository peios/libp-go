package sd_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/peios/libp-go/sd"
)

// s is a msgpack fixstr.
func s(text string) []byte { return append([]byte{0xa0 | byte(len(text))}, text...) }

func cat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

// PGSS §6.7: kind, then the object's fields under the kind's own name.
func TestEncodeAuditContextServiceExample(t *testing.T) {
	got, err := sd.EncodeAuditContext("service", sd.AuditString("name", "jellyfin"))
	if err != nil {
		t.Fatal(err)
	}
	want := cat([]byte{0x82}, s("kind"), s("service"), s("service"), []byte{0x81}, s("name"), s("jellyfin"))
	if !bytes.Equal(got, want) {
		t.Fatalf("got % x, want % x", got, want)
	}
	if err := sd.ValidateAuditContext(got); err != nil {
		t.Fatal(err)
	}
}

func TestEncodeAuditContextKindAlone(t *testing.T) {
	got, err := sd.EncodeAuditContext("system")
	if err != nil {
		t.Fatal(err)
	}
	if want := cat([]byte{0x81}, s("kind"), s("system")); !bytes.Equal(got, want) {
		t.Fatalf("got % x, want % x", got, want)
	}
}

func TestEncodeAuditContextScalarsInSmallestForm(t *testing.T) {
	got, err := sd.EncodeAuditContext("job",
		sd.AuditUint("count", 300),
		sd.AuditInt("delta", -5),
		sd.AuditInt("wide", -200),
		sd.AuditBool("enabled", true),
		sd.AuditBytes("digest", []byte{0xde, 0xad}),
		sd.AuditString("label", ""),
		sd.AuditSID("owner", sd.LocalSystem.SID()),
	)
	if err != nil {
		t.Fatal(err)
	}
	sid := sd.LocalSystem.SID().Bytes()
	want := cat([]byte{0x82}, s("kind"), s("job"), s("job"), []byte{0x87},
		s("count"), []byte{0xcd, 0x01, 0x2c},
		s("delta"), []byte{0xfb},
		s("wide"), []byte{0xd1, 0xff, 0x38},
		s("enabled"), []byte{0xc3},
		s("digest"), []byte{0xc4, 0x02, 0xde, 0xad},
		s("label"), []byte{0xa0},
		s("owner"), []byte{0xc4, byte(len(sid))}, sid,
	)
	if !bytes.Equal(got, want) {
		t.Fatalf("got % x, want % x", got, want)
	}
}

func TestEncodeAuditContextLongValuesAndManyFields(t *testing.T) {
	var fields []sd.AuditField
	for _, k := range strings.Fields("a b c d e f g h i j k l m n o p q r s t") {
		fields = append(fields, sd.AuditUint(k, 1))
	}
	fields = append(fields, sd.AuditString("path", strings.Repeat("x", 300)))
	got, err := sd.EncodeAuditContext("event-namespace", fields...)
	if err != nil {
		t.Fatal(err)
	}
	if i := bytes.IndexByte(got, 0xde); i < 0 || !bytes.Equal(got[i:i+3], []byte{0xde, 0x00, 21}) {
		t.Fatalf("want a map16 body of 21 fields: % x", got)
	}
	tail := got[len(got)-303 : len(got)-300]
	if !bytes.Equal(tail, []byte{0xda, 0x01, 0x2c}) {
		t.Fatalf("want a str16 header, got % x", tail)
	}
}

func TestEncodeAuditContextRefusals(t *testing.T) {
	name := sd.AuditString("name", "x")
	for _, kind := range []string{"", "Service", "9lives", "a--b", "-a", "a-", "a.b", "a_b"} {
		if _, err := sd.EncodeAuditContext(kind, name); !errors.Is(err, sd.ErrBadAuditContext) {
			t.Errorf("kind %q: got %v", kind, err)
		}
	}
	for _, key := range []string{"", "Name", "na me", "a.b"} {
		if _, err := sd.EncodeAuditContext("service", sd.AuditString(key, "x")); !errors.Is(err, sd.ErrBadAuditContext) {
			t.Errorf("key %q: got %v", key, err)
		}
	}
	cases := map[string][]sd.AuditField{
		"repeated key": {sd.AuditString("name", "a"), sd.AuditString("name", "b")},
		"not UTF-8":    {sd.AuditString("name", "\xe9")},
		"over 4096":    {sd.AuditString("name", strings.Repeat("x", 4096))},
	}
	for what, fields := range cases {
		if _, err := sd.EncodeAuditContext("service", fields...); !errors.Is(err, sd.ErrBadAuditContext) {
			t.Errorf("%s: got %v", what, err)
		}
	}
	if _, err := sd.EncodeAuditContext("service", sd.AuditString("name", strings.Repeat("x", 4096-40))); err != nil {
		t.Errorf("a context that fits: %v", err)
	}
}

func TestValidateAuditContextMatchesTheKernel(t *testing.T) {
	kind := func(k string) []byte { return cat(s("kind"), s(k)) }
	accepted := [][]byte{
		cat([]byte{0x81}, kind("service")),
		cat([]byte{0x82}, s("service"), []byte{0x81}, s("name"), s("a"), kind("service")),
		// Shapes the kernel takes though the encoder would not write them.
		cat([]byte{0x82}, kind("service"), s("service"), []byte{0x81}, s("name"), []byte{0xc0}),
		cat([]byte{0x82}, kind("service"), s("service"), []byte{0x81}, s("ids"), []byte{0x91, 0x01}),
	}
	for _, b := range accepted {
		if err := sd.ValidateAuditContext(b); err != nil {
			t.Errorf("% x: %v", b, err)
		}
	}
	refused := [][]byte{
		nil,
		{0x80},
		{0xc0},
		cat([]byte{0x81}, s("kind"), []byte{0x01}),
		cat([]byte{0x81}, kind("Service")),
		cat([]byte{0x82}, kind("a"), kind("a")),
		cat([]byte{0x81}, s("service"), []byte{0x81}, s("name"), s("a")),
		cat([]byte{0x82}, kind("service"), s("job"), []byte{0x81}, s("name"), s("a")),
		cat([]byte{0x82}, kind("service"), s("service"), []byte{0x80}),
		cat([]byte{0x82}, kind("service"), s("service"), s("x")),
		cat([]byte{0x82}, kind("service"), s("service"), []byte{0x81}, s("Name"), s("a")),
		cat([]byte{0x83}, kind("service"), s("service"), []byte{0x81}, s("n"), s("a"), s("x"), []byte{0x01}),
		cat([]byte{0x81}, kind("service"), []byte{0x00}),
		cat([]byte{0x82}, kind("service"), s("service"), []byte{0x81}, s("n"), []byte{0xa1, 0xff}),
		cat([]byte{0x82}, kind("service"), s("service"), []byte{0x81}, s("n"), []byte{0xc1}),
		s("events:kacs.*"),
	}
	for _, b := range refused {
		if err := sd.ValidateAuditContext(b); !errors.Is(err, sd.ErrBadAuditContext) {
			t.Errorf("% x: got %v", b, err)
		}
	}
}

// The context lands one level below the record's payload root, so it may
// nest one level less than the emit limit (32): 31 levels, of which the
// top map and the body take two.
func TestValidateAuditContextNesting(t *testing.T) {
	nested := func(arrays int) []byte {
		b := cat([]byte{0x82}, s("kind"), s("k"), s("k"), []byte{0x81}, s("v"))
		b = append(b, bytes.Repeat([]byte{0x91}, arrays)...)
		return append(b, 0x01)
	}
	if err := sd.ValidateAuditContext(nested(28)); err != nil {
		t.Errorf("28 arrays: %v", err)
	}
	if err := sd.ValidateAuditContext(nested(29)); err == nil {
		t.Error("29 arrays accepted")
	}
}

func TestValidateAuditContextLength(t *testing.T) {
	pad := func(n int) []byte {
		b := cat([]byte{0x82}, s("kind"), s("k"), s("k"), []byte{0x81}, s("v"), []byte{0xc5})
		body := n - len(b) - 2
		b = append(b, byte(body>>8), byte(body))
		return append(b, make([]byte, body)...)
	}
	if err := sd.ValidateAuditContext(pad(4096)); err != nil {
		t.Errorf("4096 bytes: %v", err)
	}
	if err := sd.ValidateAuditContext(pad(4097)); err == nil {
		t.Error("4097 bytes accepted")
	}
}

// A malformed context fails the check before the syscall, so this holds
// on any kernel.
func TestCheckRefusesAMalformedAuditContext(t *testing.T) {
	sdBytes, err := sd.Descriptor{
		Owner: sd.LocalSystem.SID(),
		Group: sd.BuiltinAdministrators.SID(),
		DACL:  &sd.ACL{},
	}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	req := sd.CheckRequest{SD: sdBytes, DesiredAccess: sd.AccessReadControl, AuditContext: s("events:kacs.*")}
	if _, err := sd.Check(req); !errors.Is(err, sd.ErrBadAuditContext) {
		t.Fatalf("Check: got %v", err)
	}
	req.ObjectTree = []sd.ObjectNode{{}}
	if _, err := sd.CheckList(req); !errors.Is(err, sd.ErrBadAuditContext) {
		t.Fatalf("CheckList: got %v", err)
	}
}
