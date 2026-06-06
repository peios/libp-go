package sd

import "fmt"

// allInheritFlags is the four inheritance-control flags as one mask —
// cleared when an inheritable ACE is "consumed" onto a leaf child.
const allInheritFlags AceFlags = FlagObjectInherit | FlagContainerInherit |
	FlagNoPropagateInherit | FlagInheritOnly

// ComputeInheritedACEs returns the ACEs a child inherits from parentDACL,
// per MS-DTYP §2.5.3.4.1. Each returned ACE has FlagInherited set; an
// ACE inheritable to no child kind is dropped.
func ComputeInheritedACEs(parentDACL ACL, childIsContainer bool) []ACE {
	var out []ACE
	for _, ace := range parentDACL.Entries {
		f := ace.Flags
		oi := f&FlagObjectInherit != 0
		ci := f&FlagContainerInherit != 0
		np := f&FlagNoPropagateInherit != 0
		if !oi && !ci {
			continue
		}

		var newFlags AceFlags
		switch {
		case !childIsContainer:
			// File child: only OBJECT_INHERIT ACEs apply, and they
			// terminate — every inheritance flag is cleared.
			if !oi {
				continue
			}
			newFlags = (f &^ allInheritFlags) | FlagInherited
		case np:
			// NO_PROPAGATE on a container: a CI ACE applies here and
			// stops; an OI-only ACE reaches no further and is dropped.
			if !ci {
				continue
			}
			newFlags = (f &^ allInheritFlags) | FlagInherited
		case ci:
			// Container child, CI set: applies here and keeps
			// propagating — only NP and INHERIT_ONLY are cleared.
			newFlags = (f &^ (FlagNoPropagateInherit | FlagInheritOnly)) | FlagInherited
		default:
			// OBJECT_INHERIT alone on a container: does not apply here
			// but propagates inward — INHERIT_ONLY is set.
			newFlags = (f &^ FlagNoPropagateInherit) | FlagInheritOnly | FlagInherited
		}

		child := ace // struct copy; Raw / GUID pointers are shared read-only
		child.Flags = newFlags
		out = append(out, child)
	}
	return out
}

// Reinherit re-derives a child security descriptor's inheritance from a
// parent: it drops the child's inherited DACL ACEs and appends a fresh
// inherited set computed from the parent's DACL. The child's explicit
// ACEs come first, then the inherited ones (the MS-DTYP §2.5.2.1 order).
//
// Owner, group, and SACL of the child pass through; the
// auto-inherited / protected control bits are preserved. Reinherit does
// not itself honour ControlDACLProtected — a caller that wants to skip
// a protected child must check it first. Both inputs must be
// self-relative.
func Reinherit(parentSD, childSD []byte, childIsContainer bool) ([]byte, error) {
	parent, err := ParseDescriptor(parentSD)
	if err != nil {
		return nil, fmt.Errorf("libp/sd: reinherit: parent: %w", err)
	}
	child, err := ParseDescriptor(childSD)
	if err != nil {
		return nil, fmt.Errorf("libp/sd: reinherit: child: %w", err)
	}
	if child.Control&ControlSelfRelative == 0 {
		return nil, ErrNotSelfRelative
	}

	var inherited []ACE
	if parent.DACL != nil {
		inherited = ComputeInheritedACEs(*parent.DACL, childIsContainer)
	}

	out := Descriptor{
		Control: child.Control & (ControlDACLAutoInherited | ControlDACLProtected |
			ControlSACLAutoInherited | ControlSACLProtected),
		Owner: child.Owner,
		Group: child.Group,
		SACL:  child.SACL,
	}
	hadDACL := child.DACL != nil
	var dacl ACL
	if child.DACL != nil {
		for _, a := range child.DACL.Entries {
			if a.Flags&FlagInherited == 0 {
				dacl.Entries = append(dacl.Entries, a)
			}
		}
	}
	dacl.Entries = append(dacl.Entries, inherited...)
	if hadDACL || len(dacl.Entries) > 0 {
		out.DACL = &dacl
	}
	return out.Marshal()
}
