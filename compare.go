package gontsd

import (
	"bytes"
	"fmt"
)

// DiffType represents the type of change detected between two ACEs.
type DiffType int

const (
	DiffAdded DiffType = iota
	DiffRemoved
	DiffModified
	DiffReordered
)

func (d DiffType) String() string {
	switch d {
	case DiffAdded:
		return "Added"
	case DiffRemoved:
		return "Removed"
	case DiffModified:
		return "Modified"
	case DiffReordered:
		return "Reordered"
	default:
		return "Unknown"
	}
}

// ACEDiff represents a single change to an ACE.
type ACEDiff struct {
	Type     DiffType
	Position int // Index in the ACL
	OldACE   ACE // nil if Added
	NewACE   ACE // nil if Removed
}

// ACLDiff represents the changes between two ACLs.
type ACLDiff struct {
	RevisionChanged bool
	OldRevision     uint8
	NewRevision     uint8
	ACEDiffs        []ACEDiff
}

// DiffResult contains all changes detected between two SecurityDescriptors.
type DiffResult struct {
	OwnerChanged bool
	OldOwner     *SID
	NewOwner     *SID

	GroupChanged bool
	OldGroup     *SID
	NewGroup     *SID

	DACLDiff *ACLDiff // nil if DACL unchanged
	SACLDiff *ACLDiff // nil if SACL unchanged

	ControlFlagsChanged bool
	OldControlFlags     uint16
	NewControlFlags     uint16
}

// HasChanges returns true if any differences were detected.
func (d *DiffResult) HasChanges() bool {
	if d == nil {
		return false
	}
	return d.OwnerChanged || d.GroupChanged || d.ControlFlagsChanged ||
		d.DACLDiff != nil || d.SACLDiff != nil
}

// Compare compares two SecurityDescriptors and returns the differences.
func Compare(old, new *SecurityDescriptor) *DiffResult {
	result := &DiffResult{}

	if !sidEqual(old.OwnerSID, new.OwnerSID) {
		result.OwnerChanged = true
		result.OldOwner = old.OwnerSID
		result.NewOwner = new.OwnerSID
	}

	if !sidEqual(old.GroupSID, new.GroupSID) {
		result.GroupChanged = true
		result.OldGroup = old.GroupSID
		result.NewGroup = new.GroupSID
	}

	if old.ControlFlags != new.ControlFlags {
		result.ControlFlagsChanged = true
		result.OldControlFlags = old.ControlFlags
		result.NewControlFlags = new.ControlFlags
	}

	result.DACLDiff = compareACL(old.DACL, new.DACL)
	result.SACLDiff = compareACL(old.SACL, new.SACL)

	return result
}

func sidEqual(a, b *SID) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.Parsed == b.Parsed
}

func compareACL(old, new *ACL) *ACLDiff {
	if old == nil && new == nil {
		return nil
	}

	if old == nil {
		diff := &ACLDiff{
			RevisionChanged: true,
			OldRevision:     0,
			NewRevision:     new.Revision,
		}
		for i, ace := range new.ACEs {
			diff.ACEDiffs = append(diff.ACEDiffs, ACEDiff{
				Type:     DiffAdded,
				Position: i,
				NewACE:   ace,
			})
		}
		return diff
	}

	if new == nil {
		diff := &ACLDiff{
			RevisionChanged: true,
			OldRevision:     old.Revision,
			NewRevision:     0,
		}
		for i, ace := range old.ACEs {
			diff.ACEDiffs = append(diff.ACEDiffs, ACEDiff{
				Type:     DiffRemoved,
				Position: i,
				OldACE:   ace,
			})
		}
		return diff
	}

	diff := &ACLDiff{}

	if old.Revision != new.Revision {
		diff.RevisionChanged = true
		diff.OldRevision = old.Revision
		diff.NewRevision = new.Revision
	}

	diff.ACEDiffs = compareACEs(old.ACEs, new.ACEs)

	if !diff.RevisionChanged && len(diff.ACEDiffs) == 0 {
		return nil
	}

	return diff
}

func compareACEs(oldACEs, newACEs []ACE) []ACEDiff {
	var diffs []ACEDiff

	oldByID := make(map[string][]indexedACE)
	newByID := make(map[string][]indexedACE)

	for i, ace := range oldACEs {
		id := aceIdentity(ace)
		oldByID[id] = append(oldByID[id], indexedACE{index: i, ace: ace})
	}
	for i, ace := range newACEs {
		id := aceIdentity(ace)
		newByID[id] = append(newByID[id], indexedACE{index: i, ace: ace})
	}

	matchedOld := make(map[int]bool)
	matchedNew := make(map[int]bool)

	for i := 0; i < len(oldACEs) && i < len(newACEs); i++ {
		if aceEqual(oldACEs[i], newACEs[i]) {
			matchedOld[i] = true
			matchedNew[i] = true
		}
	}

	for id, oldItems := range oldByID {
		if newItems, exists := newByID[id]; exists {
			for _, oldItem := range oldItems {
				if matchedOld[oldItem.index] {
					continue
				}
				for _, newItem := range newItems {
					if matchedNew[newItem.index] {
						continue
					}
					if aceEqual(oldItem.ace, newItem.ace) {
						// Found same ACE at different position
						diffs = append(diffs, ACEDiff{
							Type:     DiffReordered,
							Position: newItem.index,
							OldACE:   oldItem.ace,
							NewACE:   newItem.ace,
						})
						matchedOld[oldItem.index] = true
						matchedNew[newItem.index] = true
						break
					}
				}
			}
		}
	}

	for i, oldACE := range oldACEs {
		if matchedOld[i] {
			continue
		}
		oldID := aceIdentity(oldACE)
		if newItems, exists := newByID[oldID]; exists {
			for _, newItem := range newItems {
				if matchedNew[newItem.index] {
					continue
				}
				diffs = append(diffs, ACEDiff{
					Type:     DiffModified,
					Position: newItem.index,
					OldACE:   oldACE,
					NewACE:   newItem.ace,
				})
				matchedOld[i] = true
				matchedNew[newItem.index] = true
				break
			}
		}
	}

	for i, ace := range oldACEs {
		if !matchedOld[i] {
			diffs = append(diffs, ACEDiff{
				Type:     DiffRemoved,
				Position: i,
				OldACE:   ace,
			})
		}
	}

	for i, ace := range newACEs {
		if !matchedNew[i] {
			diffs = append(diffs, ACEDiff{
				Type:     DiffAdded,
				Position: i,
				NewACE:   ace,
			})
		}
	}

	return diffs
}

type indexedACE struct {
	index int
	ace   ACE
}

func aceIdentity(ace ACE) string {
	sid := ace.GetSID()
	if sid == nil {
		return fmt.Sprintf("0x%02X:<nil>", ace.Type())
	}
	return fmt.Sprintf("0x%02X:%s", ace.Type(), sid.Parsed)
}

func aceEqual(a, b ACE) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if a.Type() != b.Type() {
		return false
	}
	if a.GetMask() != b.GetMask() {
		return false
	}
	if !sidEqual(a.GetSID(), b.GetSID()) {
		return false
	}
	if aceFlags(a) != aceFlags(b) {
		return false
	}
	if a.GetObjectTypeGUID() != b.GetObjectTypeGUID() {
		return false
	}
	if a.GetInheritedObjectTypeGUID() != b.GetInheritedObjectTypeGUID() {
		return false
	}
	if !bytes.Equal(aceAppData(a), aceAppData(b)) {
		return false
	}
	return true
}

func aceFlags(a ACE) uint8 {
	switch v := a.(type) {
	case *AccessAllowedACE:
		return v.Header.AceFlags
	case *AccessDeniedACE:
		return v.Header.AceFlags
	case *AccessAllowedObjectACE:
		return v.Header.AceFlags
	case *AccessDeniedObjectACE:
		return v.Header.AceFlags
	case *AccessAllowedCallbackACE:
		return v.Header.AceFlags
	case *AccessDeniedCallbackACE:
		return v.Header.AceFlags
	case *AccessAllowedCallbackObjectACE:
		return v.Header.AceFlags
	case *AccessDeniedCallbackObjectACE:
		return v.Header.AceFlags
	case *RawACE:
		return v.Header.AceFlags
	}
	return 0
}

func aceAppData(a ACE) []byte {
	switch v := a.(type) {
	case *AccessAllowedCallbackACE:
		return v.ApplicationData
	case *AccessDeniedCallbackACE:
		return v.ApplicationData
	case *AccessAllowedCallbackObjectACE:
		return v.ApplicationData
	case *AccessDeniedCallbackObjectACE:
		return v.ApplicationData
	}
	return nil
}
