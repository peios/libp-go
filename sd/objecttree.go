package sd

import "encoding/binary"

// ObjectNode is one node of an object-type tree, as passed to an
// object-tree access check. The root node is Level 0; its children are
// Level 1, and so on — the tree structure is implied by the depth
// sequence of a flat, depth-ordered node list.
type ObjectNode struct {
	Level uint16
	GUID  GUID
}

// EncodeObjectTree encodes a depth-ordered list of object-type nodes
// into the flat 20-byte-per-node wire array. A nil or empty list encodes
// to nil.
func EncodeObjectTree(nodes []ObjectNode) []byte {
	if len(nodes) == 0 {
		return nil
	}
	out := make([]byte, 0, len(nodes)*20)
	for _, n := range nodes {
		out = binary.LittleEndian.AppendUint16(out, n.Level)
		out = binary.LittleEndian.AppendUint16(out, 0) // reserved
		out = append(out, n.GUID[:]...)
	}
	return out
}
