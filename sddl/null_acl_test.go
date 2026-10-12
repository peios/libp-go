package sddl

import (
	"bytes"
	"encoding/binary"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/peios/libp-go/sd"
)

func TestNullACLKernelContractVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/null-acl-vectors.tsv")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		t.Run(fields[0], func(t *testing.T) {
			d := mustParse(t, fields[0])
			wire, err := d.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			control, err := strconv.ParseUint(fields[2], 16, 16)
			if err != nil {
				t.Fatal(err)
			}
			if got := binary.LittleEndian.Uint16(wire[2:4]); got != uint16(control) {
				t.Fatalf("control = %04x, want %04x", got, control)
			}
			for _, acl := range []struct {
				bit    uint16
				offset int
			}{{4, 16}, {16, 12}} {
				off := binary.LittleEndian.Uint32(wire[acl.offset : acl.offset+4])
				if (uint16(control)&acl.bit == 0) != (off == 0) {
					t.Fatalf("PRESENT and offset disagree: control=%04x offset=%d", control, off)
				}
			}
			out, err := Format(d)
			if err != nil {
				t.Fatal(err)
			}
			if out != fields[1] {
				t.Fatalf("format = %q, want %q", out, fields[1])
			}
			reparsed := mustParse(t, out)
			again, err := reparsed.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(wire, again) {
				t.Fatal("canonical round trip changed the descriptor")
			}
		})
	}
}

func TestNullACLRejectsMalformedCombinations(t *testing.T) {
	for _, section := range []string{"D:", "S:"} {
		for _, bad := range []string{"NO_ACCESS_CONTROL(A;;GA;;;WD)",
			"NO_ACCESS_CONTROLNO_ACCESS_CONTROL", "NO_ACCESS_CONTRO", "ANO_ACCESS_CONTROLR"} {
			if _, err := Parse(section + bad); err == nil {
				t.Errorf("accepted %q", section+bad)
			}
		}
	}
	for _, control := range []sd.Control{sd.ControlDACLPresent, sd.ControlSACLPresent} {
		if _, err := Format(sd.Descriptor{Control: control}); err == nil {
			t.Errorf("formatted invalid PRESENT-without-data control %#x", control)
		}
	}
}
