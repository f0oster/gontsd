package gontsd

import "bytes"

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
	return aceTypePrefix(ace) + ":" + ace.GetSID().Parsed
}

func aceTypePrefix(ace ACE) string {
	switch ace.(type) {
	case *AccessAllowedACE:
		return "allowed"
	case *AccessDeniedACE:
		return "denied"
	case *AccessAllowedObjectACE:
		return "allowed-object"
	case *AccessDeniedObjectACE:
		return "denied-object"
	case *AccessAllowedCallbackACE:
		return "allowed-callback"
	case *AccessDeniedCallbackACE:
		return "denied-callback"
	case *AccessAllowedCallbackObjectACE:
		return "allowed-callback-object"
	case *AccessDeniedCallbackObjectACE:
		return "denied-callback-object"
	default:
		return "unknown"
	}
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

	switch aTyped := a.(type) {
	case *AccessAllowedACE:
		bTyped, ok := b.(*AccessAllowedACE)
		if !ok {
			return false
		}
		return accessAllowedACEEqual(aTyped, bTyped)
	case *AccessDeniedACE:
		bTyped, ok := b.(*AccessDeniedACE)
		if !ok {
			return false
		}
		return accessDeniedACEEqual(aTyped, bTyped)
	case *AccessAllowedObjectACE:
		bTyped, ok := b.(*AccessAllowedObjectACE)
		if !ok {
			return false
		}
		return accessAllowedObjectACEEqual(aTyped, bTyped)
	case *AccessDeniedObjectACE:
		bTyped, ok := b.(*AccessDeniedObjectACE)
		if !ok {
			return false
		}
		return accessDeniedObjectACEEqual(aTyped, bTyped)
	case *AccessAllowedCallbackACE:
		bTyped, ok := b.(*AccessAllowedCallbackACE)
		if !ok {
			return false
		}
		return accessAllowedCallbackACEEqual(aTyped, bTyped)
	case *AccessDeniedCallbackACE:
		bTyped, ok := b.(*AccessDeniedCallbackACE)
		if !ok {
			return false
		}
		return accessDeniedCallbackACEEqual(aTyped, bTyped)
	case *AccessAllowedCallbackObjectACE:
		bTyped, ok := b.(*AccessAllowedCallbackObjectACE)
		if !ok {
			return false
		}
		return accessAllowedCallbackObjectACEEqual(aTyped, bTyped)
	case *AccessDeniedCallbackObjectACE:
		bTyped, ok := b.(*AccessDeniedCallbackObjectACE)
		if !ok {
			return false
		}
		return accessDeniedCallbackObjectACEEqual(aTyped, bTyped)
	default:
		return false
	}
}

func accessAllowedACEEqual(a, b *AccessAllowedACE) bool {
	if a.Header.AceType != b.Header.AceType {
		return false
	}
	if a.Header.AceFlags != b.Header.AceFlags {
		return false
	}
	if a.Mask != b.Mask {
		return false
	}
	return sidEqual(a.SID, b.SID)
}

func accessDeniedACEEqual(a, b *AccessDeniedACE) bool {
	if a.Header.AceType != b.Header.AceType {
		return false
	}
	if a.Header.AceFlags != b.Header.AceFlags {
		return false
	}
	if a.Mask != b.Mask {
		return false
	}
	return sidEqual(a.SID, b.SID)
}

func accessAllowedObjectACEEqual(a, b *AccessAllowedObjectACE) bool {
	if a.Header.AceType != b.Header.AceType {
		return false
	}
	if a.Header.AceFlags != b.Header.AceFlags {
		return false
	}
	if a.Mask != b.Mask {
		return false
	}
	if a.ObjectFlags != b.ObjectFlags {
		return false
	}
	if !bytes.Equal(a.ObjectType[:], b.ObjectType[:]) {
		return false
	}
	if !bytes.Equal(a.InheritedObjectType[:], b.InheritedObjectType[:]) {
		return false
	}
	return sidEqual(a.SID, b.SID)
}

func accessDeniedObjectACEEqual(a, b *AccessDeniedObjectACE) bool {
	if a.Header.AceType != b.Header.AceType {
		return false
	}
	if a.Header.AceFlags != b.Header.AceFlags {
		return false
	}
	if a.Mask != b.Mask {
		return false
	}
	if a.ObjectFlags != b.ObjectFlags {
		return false
	}
	if !bytes.Equal(a.ObjectType[:], b.ObjectType[:]) {
		return false
	}
	if !bytes.Equal(a.InheritedObjectType[:], b.InheritedObjectType[:]) {
		return false
	}
	return sidEqual(a.SID, b.SID)
}

func accessAllowedCallbackACEEqual(a, b *AccessAllowedCallbackACE) bool {
	if a.Header.AceType != b.Header.AceType {
		return false
	}
	if a.Header.AceFlags != b.Header.AceFlags {
		return false
	}
	if a.Mask != b.Mask {
		return false
	}
	if !bytes.Equal(a.ApplicationData, b.ApplicationData) {
		return false
	}
	return sidEqual(a.SID, b.SID)
}

func accessDeniedCallbackACEEqual(a, b *AccessDeniedCallbackACE) bool {
	if a.Header.AceType != b.Header.AceType {
		return false
	}
	if a.Header.AceFlags != b.Header.AceFlags {
		return false
	}
	if a.Mask != b.Mask {
		return false
	}
	if !bytes.Equal(a.ApplicationData, b.ApplicationData) {
		return false
	}
	return sidEqual(a.SID, b.SID)
}

func accessAllowedCallbackObjectACEEqual(a, b *AccessAllowedCallbackObjectACE) bool {
	if a.Header.AceType != b.Header.AceType {
		return false
	}
	if a.Header.AceFlags != b.Header.AceFlags {
		return false
	}
	if a.Mask != b.Mask {
		return false
	}
	if a.ObjectFlags != b.ObjectFlags {
		return false
	}
	if !bytes.Equal(a.ObjectType[:], b.ObjectType[:]) {
		return false
	}
	if !bytes.Equal(a.InheritedObjectType[:], b.InheritedObjectType[:]) {
		return false
	}
	if !bytes.Equal(a.ApplicationData, b.ApplicationData) {
		return false
	}
	return sidEqual(a.SID, b.SID)
}

func accessDeniedCallbackObjectACEEqual(a, b *AccessDeniedCallbackObjectACE) bool {
	if a.Header.AceType != b.Header.AceType {
		return false
	}
	if a.Header.AceFlags != b.Header.AceFlags {
		return false
	}
	if a.Mask != b.Mask {
		return false
	}
	if a.ObjectFlags != b.ObjectFlags {
		return false
	}
	if !bytes.Equal(a.ObjectType[:], b.ObjectType[:]) {
		return false
	}
	if !bytes.Equal(a.InheritedObjectType[:], b.InheritedObjectType[:]) {
		return false
	}
	if !bytes.Equal(a.ApplicationData, b.ApplicationData) {
		return false
	}
	return sidEqual(a.SID, b.SID)
}
