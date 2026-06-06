package sddl

import (
	"encoding/hex"
	"fmt"

	"github.com/peios/libp-go/sd"
)

// parseGUID decodes the 8-4-4-4-12 textual GUID used in object ACEs
// into the mixed-endian 16-byte wire form.
func parseGUID(s string) (sd.GUID, error) {
	var g sd.GUID
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return g, fmt.Errorf("malformed GUID %q", s)
	}
	raw, err := hex.DecodeString(s[0:8] + s[9:13] + s[14:18] + s[19:23] + s[24:36])
	if err != nil {
		return g, fmt.Errorf("malformed GUID %q", s)
	}
	// Data1 (4 bytes) and Data2/Data3 (2 bytes each) are little-endian
	// on the wire; Data4 (the trailing 8 bytes) is kept in order.
	g[0], g[1], g[2], g[3] = raw[3], raw[2], raw[1], raw[0]
	g[4], g[5] = raw[5], raw[4]
	g[6], g[7] = raw[7], raw[6]
	copy(g[8:], raw[8:16])
	return g, nil
}

// formatGUID renders a wire GUID in the 8-4-4-4-12 textual form.
func formatGUID(g sd.GUID) string {
	display := []byte{
		g[3], g[2], g[1], g[0],
		g[5], g[4],
		g[7], g[6],
		g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15],
	}
	h := hex.EncodeToString(display)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}
