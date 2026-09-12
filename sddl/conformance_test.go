package sddl

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"testing"
)

// The shared SDDL conformance corpus (PEI-562). The same file, byte for byte,
// lives at libpeios/src/security/sddl/testdata/sddl-conformance.txt and is
// read by that crate's grammar tests. Its header explains why it is a copy
// rather than a genuinely shared file.
//
// conformanceRevision must match the corpus's `# revision:` line. Bumping the
// corpus without bumping this constant fails here, which is how a corpus
// updated on one side and not the other gets caught.
const (
	conformancePath     = "testdata/sddl-conformance.txt"
	conformanceRevision = 1
)

type conformanceCase struct {
	line int
	kind string
	arg  string
	want string
}

// readConformance parses the corpus, checking its declared revision.
func readConformance(t *testing.T) []conformanceCase {
	t.Helper()
	f, err := os.Open(conformancePath)
	if err != nil {
		t.Fatalf("open corpus: %v", err)
	}
	defer f.Close()

	var (
		cases    []conformanceCase
		revision = -1
		scanner  = bufio.NewScanner(f)
		lineNo   int
	)
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			if rest, ok := strings.CutPrefix(line, "# revision:"); ok {
				revision, err = strconv.Atoi(strings.TrimSpace(rest))
				if err != nil {
					t.Fatalf("%s:%d: malformed revision line %q", conformancePath, lineNo, line)
				}
			}
			continue
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		c := conformanceCase{line: lineNo, kind: fields[0]}
		switch c.kind {
		case "rights", "sid":
			if len(fields) != 3 {
				t.Fatalf("%s:%d: %q takes two fields, got %d", conformancePath, lineNo, c.kind, len(fields)-1)
			}
			c.arg, c.want = fields[1], fields[2]
		case "badrights":
			if len(fields) != 2 {
				t.Fatalf("%s:%d: %q takes one field, got %d", conformancePath, lineNo, c.kind, len(fields)-1)
			}
			c.arg = fields[1]
		default:
			t.Fatalf("%s:%d: unknown case kind %q", conformancePath, lineNo, c.kind)
		}
		cases = append(cases, c)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	if revision != conformanceRevision {
		t.Fatalf("corpus declares revision %d, this suite expects %d — the corpus and its "+
			"copy in libpeios must be updated together", revision, conformanceRevision)
	}
	if len(cases) == 0 {
		t.Fatal("corpus is empty")
	}
	return cases
}

// TestConformanceRights checks every rights field in the shared corpus,
// including the mnemonic-plus-trailing-hex form libpeios has always accepted
// and libp-go refused until PEI-562.
func TestConformanceRights(t *testing.T) {
	var checked int
	for _, c := range readConformance(t) {
		if c.kind != "rights" {
			continue
		}
		checked++
		want64, err := strconv.ParseUint(strings.TrimPrefix(c.want, "0x"), 16, 32)
		if err != nil {
			t.Fatalf("%s:%d: malformed expected mask %q", conformancePath, c.line, c.want)
		}
		got, err := parseMask(c.arg)
		if err != nil {
			t.Errorf("%s:%d: parseMask(%q): %v", conformancePath, c.line, c.arg, err)
			continue
		}
		if got != uint32(want64) {
			t.Errorf("%s:%d: parseMask(%q) = 0x%08x, want %s",
				conformancePath, c.line, c.arg, got, c.want)
		}
	}
	if checked == 0 {
		t.Fatal("no rights cases in the corpus")
	}
}

// TestConformanceBadRights checks the fields both implementations reject.
func TestConformanceBadRights(t *testing.T) {
	var checked int
	for _, c := range readConformance(t) {
		if c.kind != "badrights" {
			continue
		}
		checked++
		if got, err := parseMask(c.arg); err == nil {
			t.Errorf("%s:%d: parseMask(%q) = 0x%08x, want an error",
				conformancePath, c.line, c.arg, got)
		}
	}
	if checked == 0 {
		t.Fatal("no badrights cases in the corpus")
	}
}

// TestConformanceSIDAliases round-trips every absolute alias through the
// public API: the alias parses to the SID the corpus names, and formatting
// that SID emits the alias again. This is the round trip PEI-562 was filed
// for — an alias one side emits and the other has never heard of.
func TestConformanceSIDAliases(t *testing.T) {
	var checked int
	for _, c := range readConformance(t) {
		if c.kind != "sid" {
			continue
		}
		checked++
		text := "O:" + c.arg
		d, err := Parse(text)
		if err != nil {
			t.Errorf("%s:%d: Parse(%q): %v", conformancePath, c.line, text, err)
			continue
		}
		if got := d.Owner.String(); got != c.want {
			t.Errorf("%s:%d: Parse(%q) owner = %s, want %s",
				conformancePath, c.line, text, got, c.want)
			continue
		}
		out, err := Format(d)
		if err != nil {
			t.Errorf("%s:%d: Format(%q): %v", conformancePath, c.line, text, err)
			continue
		}
		if out != text {
			t.Errorf("%s:%d: Format(Parse(%q)) = %q, want %q",
				conformancePath, c.line, text, out, text)
		}
	}
	if checked == 0 {
		t.Fatal("no sid cases in the corpus")
	}
}

// TestMixedRightsFieldInWholeDescriptor is the case from the ticket, through
// the public parser rather than parseMask alone: /tmp's descriptor wants
// FILE_ADD_FILE|FILE_ADD_SUBDIRECTORY, which have no two-letter mnemonic.
func TestMixedRightsFieldInWholeDescriptor(t *testing.T) {
	d := mustParse(t, "D:(A;;FRFX0x6;;;WD)")
	if d.DACL == nil {
		t.Fatal("no DACL")
	}
	if n := len(d.DACL.Entries); n != 1 {
		t.Fatalf("DACL has %d ACEs, want 1", n)
	}
	if got := d.DACL.Entries[0].Mask; got != 0x001200af {
		t.Errorf("mask = 0x%08x, want 0x001200af", got)
	}
}
