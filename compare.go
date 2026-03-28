package gontsd

import (
	"bytes"
	"fmt"
	"strings"
)

// DiffType represents the type of change detected between two ACEs.
// Values can be combined as a bitmask (e.g. DiffModified | DiffReordered).
type DiffType int

const (
	DiffAdded     DiffType = 1 << iota // ACE exists in new but not old
	DiffRemoved                        // ACE exists in old but not new
	DiffModified                       // ACE content changed
	DiffReordered                      // ACE position changed
)

func (d DiffType) Has(flag DiffType) bool {
	return d&flag != 0
}

func (d DiffType) String() string {
	if d == 0 {
		return "Unchanged"
	}
	var parts []string
	if d.Has(DiffAdded) {
		parts = append(parts, "Added")
	}
	if d.Has(DiffRemoved) {
		parts = append(parts, "Removed")
	}
	if d.Has(DiffModified) {
		parts = append(parts, "Modified")
	}
	if d.Has(DiffReordered) {
		parts = append(parts, "Reordered")
	}
	if len(parts) == 0 {
		return "Unknown"
	}
	return strings.Join(parts, "|")
}

// ACEDiff represents a single change to an ACE.
type ACEDiff struct {
	Type        DiffType
	OldPosition int // Index in the old ACL, or -1 if Added
	NewPosition int // Index in the new ACL, or -1 if Removed
	OldACE      ACE // nil if Added
	NewACE      ACE // nil if Removed
}

// CompareAccessRights returns the access rights that were added, removed,
// and unchanged between the old and new ACE. Returns nil slices if either
// ACE is nil.
func (d ACEDiff) CompareAccessRights() (added, removed, unchanged []string) {
	if d.OldACE == nil || d.NewACE == nil {
		return nil, nil, nil
	}

	oldSet := make(map[string]bool)
	newSet := make(map[string]bool)

	for _, f := range d.OldACE.GetAccessRights() {
		oldSet[f] = true
	}
	for _, f := range d.NewACE.GetAccessRights() {
		newSet[f] = true
	}

	for _, f := range d.OldACE.GetAccessRights() {
		if !newSet[f] {
			removed = append(removed, f)
		} else {
			unchanged = append(unchanged, f)
		}
	}
	for _, f := range d.NewACE.GetAccessRights() {
		if !oldSet[f] {
			added = append(added, f)
		}
	}

	return added, removed, unchanged
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
// It detects changes to the owner, group, control flags, DACL, and SACL.
// Individual ACE changes are classified as added, removed, modified,
// reordered, or a combination. Either argument may be nil.
//
//	diff := gontsd.Compare(oldSD, newSD)
//	if diff.HasChanges() {
//	    for _, d := range diff.DACLDiff.ACEDiffs {
//	        if d.Type.Has(gontsd.DiffModified) {
//	            fmt.Printf("modified: %s\n", d.NewACE.GetSID().Parsed)
//	        }
//	    }
//	}
func Compare(old, new *SecurityDescriptor) *DiffResult {
	if old == nil && new == nil {
		return &DiffResult{}
	}
	if old == nil {
		old = &SecurityDescriptor{}
	}
	if new == nil {
		new = &SecurityDescriptor{}
	}

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
				Type:        DiffAdded,
				OldPosition: -1,
				NewPosition: i,
				NewACE:      ace,
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
				Type:        DiffRemoved,
				OldPosition: i,
				NewPosition: -1,
				OldACE:      ace,
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
	m := newACEMatcher(oldACEs, newACEs)
	m.matchUnchanged()
	m.matchReordered()
	m.matchModified()
	return m.collectDiffs()
}

type indexedACE struct {
	index int
	ace   ACE
}

// aceMatcher tracks the state of matching ACEs between two ACLs.
type aceMatcher struct {
	oldACEs    []ACE
	newACEs    []ACE
	oldByID    map[string][]indexedACE
	newByID    map[string][]indexedACE
	matchedOld map[int]bool
	matchedNew map[int]bool
	diffs      []ACEDiff
}

func newACEMatcher(oldACEs, newACEs []ACE) *aceMatcher {
	m := &aceMatcher{
		oldACEs:    oldACEs,
		newACEs:    newACEs,
		oldByID:    make(map[string][]indexedACE),
		newByID:    make(map[string][]indexedACE),
		matchedOld: make(map[int]bool),
		matchedNew: make(map[int]bool),
	}
	for i, ace := range oldACEs {
		id := aceIdentity(ace)
		m.oldByID[id] = append(m.oldByID[id], indexedACE{index: i, ace: ace})
	}
	for i, ace := range newACEs {
		id := aceIdentity(ace)
		m.newByID[id] = append(m.newByID[id], indexedACE{index: i, ace: ace})
	}
	return m
}

// matchUnchanged pairs ACEs that are identical and at the same position.
func (m *aceMatcher) matchUnchanged() {
	for i := 0; i < len(m.oldACEs) && i < len(m.newACEs); i++ {
		if aceEqual(m.oldACEs[i], m.newACEs[i]) {
			m.matchedOld[i] = true
			m.matchedNew[i] = true
		}
	}
}

// matchReordered pairs ACEs that are identical but at different positions.
func (m *aceMatcher) matchReordered() {
	for id, oldItems := range m.oldByID {
		newItems, exists := m.newByID[id]
		if !exists {
			continue
		}
		for _, oldItem := range oldItems {
			if m.matchedOld[oldItem.index] {
				continue
			}
			for _, newItem := range newItems {
				if m.matchedNew[newItem.index] {
					continue
				}
				if aceEqual(oldItem.ace, newItem.ace) {
					m.diffs = append(m.diffs, ACEDiff{
						Type:        DiffReordered,
						OldPosition: oldItem.index,
						NewPosition: newItem.index,
						OldACE:      oldItem.ace,
						NewACE:      newItem.ace,
					})
					m.matchedOld[oldItem.index] = true
					m.matchedNew[newItem.index] = true
					break
				}
			}
		}
	}
}

// matchModified pairs ACEs that share an identity but have different content.
// If the position also changed, both DiffModified and DiffReordered are set.
func (m *aceMatcher) matchModified() {
	for i, oldACE := range m.oldACEs {
		if m.matchedOld[i] {
			continue
		}
		oldID := aceIdentity(oldACE)
		newItems, exists := m.newByID[oldID]
		if !exists {
			continue
		}
		for _, newItem := range newItems {
			if m.matchedNew[newItem.index] {
				continue
			}
			diffType := DiffModified
			if newItem.index != i {
				diffType |= DiffReordered
			}
			m.diffs = append(m.diffs, ACEDiff{
				Type:        diffType,
				OldPosition: i,
				NewPosition: newItem.index,
				OldACE:      oldACE,
				NewACE:      newItem.ace,
			})
			m.matchedOld[i] = true
			m.matchedNew[newItem.index] = true
			break
		}
	}
}

// collectDiffs appends removed and added entries for any unmatched ACEs,
// then returns all collected diffs.
func (m *aceMatcher) collectDiffs() []ACEDiff {
	for i, ace := range m.oldACEs {
		if !m.matchedOld[i] {
			m.diffs = append(m.diffs, ACEDiff{
				Type:        DiffRemoved,
				OldPosition: i,
				NewPosition: -1,
				OldACE:      ace,
			})
		}
	}
	for i, ace := range m.newACEs {
		if !m.matchedNew[i] {
			m.diffs = append(m.diffs, ACEDiff{
				Type:        DiffAdded,
				OldPosition: -1,
				NewPosition: i,
				NewACE:      ace,
			})
		}
	}
	return m.diffs
}

func aceIdentity(ace ACE) string {
	sid := ace.GetSID()
	sidStr := "<nil>"
	if sid != nil {
		sidStr = sid.Parsed
	}
	if objGUID := ace.GetObjectTypeGUID(); objGUID != "" {
		return fmt.Sprintf("0x%02X:%s:%s", ace.Type(), sidStr, objGUID)
	}
	return fmt.Sprintf("0x%02X:%s", ace.Type(), sidStr)
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
	if a.GetAceFlags() != b.GetAceFlags() {
		return false
	}
	if a.GetMask() != b.GetMask() {
		return false
	}
	if !sidEqual(a.GetSID(), b.GetSID()) {
		return false
	}
	if a.GetObjectTypeGUID() != b.GetObjectTypeGUID() {
		return false
	}
	if a.GetInheritedObjectTypeGUID() != b.GetInheritedObjectTypeGUID() {
		return false
	}
	if !bytes.Equal(a.GetApplicationData(), b.GetApplicationData()) {
		return false
	}
	return true
}
