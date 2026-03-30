package gontsd

import (
	"testing"
)

func TestCompare_AddACE(t *testing.T) {
	before, err := Parse(loadFixture(t, "compare_add_ace/before.bin"), nil)
	if err != nil {
		t.Fatalf("Parse before: %v", err)
	}
	after, err := Parse(loadFixture(t, "compare_add_ace/after.bin"), nil)
	if err != nil {
		t.Fatalf("Parse after: %v", err)
	}

	diff := Compare(before, after)
	if !diff.HasChanges() {
		t.Fatal("expected changes")
	}
	if diff.OwnerChanged {
		t.Error("owner should not have changed")
	}
	if diff.GroupChanged {
		t.Error("group should not have changed")
	}
	if diff.DACLDiff == nil {
		t.Fatal("DACLDiff is nil")
	}

	var foundAdded bool
	for _, d := range diff.DACLDiff.ACEDiffs {
		if d.Type.Has(DiffAdded) {
			foundAdded = true
			if d.NewACE == nil {
				t.Error("added ACE diff has nil NewACE")
			} else if d.NewACE.SID() == nil || d.NewACE.SID().Value != "S-1-1-0" {
				t.Errorf("added ACE SID = %v, want S-1-1-0", d.NewACE.SID())
			}
		}
	}
	if !foundAdded {
		t.Error("expected a DiffAdded entry")
	}
}

func TestCompare_RemoveACE(t *testing.T) {
	before, err := Parse(loadFixture(t, "compare_remove_ace/before.bin"), nil)
	if err != nil {
		t.Fatalf("Parse before: %v", err)
	}
	after, err := Parse(loadFixture(t, "compare_remove_ace/after.bin"), nil)
	if err != nil {
		t.Fatalf("Parse after: %v", err)
	}

	diff := Compare(before, after)
	if !diff.HasChanges() {
		t.Fatal("expected changes")
	}
	if diff.DACLDiff == nil {
		t.Fatal("DACLDiff is nil")
	}

	var foundRemoved bool
	for _, d := range diff.DACLDiff.ACEDiffs {
		if d.Type.Has(DiffRemoved) {
			foundRemoved = true
			if d.OldACE == nil {
				t.Error("removed ACE diff has nil OldACE")
			} else if d.OldACE.SID() == nil || d.OldACE.SID().Value != "S-1-1-0" {
				t.Errorf("removed ACE SID = %v, want S-1-1-0", d.OldACE.SID())
			}
		}
	}
	if !foundRemoved {
		t.Error("expected a DiffRemoved entry")
	}
}

func TestCompare_ModifyMask(t *testing.T) {
	before, err := Parse(loadFixture(t, "compare_modify_mask/before.bin"), nil)
	if err != nil {
		t.Fatalf("Parse before: %v", err)
	}
	after, err := Parse(loadFixture(t, "compare_modify_mask/after.bin"), nil)
	if err != nil {
		t.Fatalf("Parse after: %v", err)
	}

	diff := Compare(before, after)
	if !diff.HasChanges() {
		t.Fatal("expected changes")
	}
	if diff.DACLDiff == nil {
		t.Fatal("DACLDiff is nil")
	}

	var foundModified bool
	for _, d := range diff.DACLDiff.ACEDiffs {
		if d.Type.Has(DiffModified) {
			foundModified = true
			if d.OldACE.Mask() == d.NewACE.Mask() {
				t.Error("modified ACE should have different masks")
			}
			if !d.OldACE.Mask().Has(RIGHT_DS_READ_PROPERTY) {
				t.Error("old mask should have ReadProperty")
			}
			if d.NewACE.Mask().Has(RIGHT_DS_READ_PROPERTY) {
				t.Error("new mask should not have ReadProperty")
			}
		}
	}
	if !foundModified {
		t.Error("expected a DiffModified entry")
	}
}

func TestCompare_Identical(t *testing.T) {
	data := loadFixture(t, "object_aces/sd.bin")
	sd, err := Parse(data, nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	diff := Compare(sd, sd)
	if diff.HasChanges() {
		t.Error("comparing SD to itself should report no changes")
	}
}

func TestCompare_NilACLs(t *testing.T) {
	sd1 := &SecurityDescriptor{Revision: 1}
	sd2 := &SecurityDescriptor{Revision: 1}

	diff := Compare(sd1, sd2)
	if diff.HasChanges() {
		t.Error("comparing two SDs with nil ACLs should report no changes")
	}
}

func TestCompare_NilOld(t *testing.T) {
	data := loadFixture(t, "object_aces/sd.bin")
	sd, err := Parse(data, nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	diff := Compare(nil, sd)
	if !diff.HasChanges() {
		t.Error("expected changes when old is nil")
	}
}

func TestCompare_NilNew(t *testing.T) {
	data := loadFixture(t, "object_aces/sd.bin")
	sd, err := Parse(data, nil)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	diff := Compare(sd, nil)
	if !diff.HasChanges() {
		t.Error("expected changes when new is nil")
	}
}

func TestCompare_BothNil(t *testing.T) {
	diff := Compare(nil, nil)
	if diff.HasChanges() {
		t.Error("expected no changes when both nil")
	}
}

func TestDiffType_Has(t *testing.T) {
	dt := DiffModified | DiffReordered
	if !dt.Has(DiffModified) {
		t.Error("expected Has(DiffModified) = true")
	}
	if !dt.Has(DiffReordered) {
		t.Error("expected Has(DiffReordered) = true")
	}
	if dt.Has(DiffAdded) {
		t.Error("expected Has(DiffAdded) = false")
	}
	if dt.Has(DiffRemoved) {
		t.Error("expected Has(DiffRemoved) = false")
	}
}

func TestCompare_NilDiffResult(t *testing.T) {
	var diff *DiffResult
	if diff.HasChanges() {
		t.Error("nil DiffResult.HasChanges() should return false")
	}
}

func TestDiffType_String(t *testing.T) {
	tests := []struct {
		dt   DiffType
		want string
	}{
		{DiffAdded, "Added"},
		{DiffRemoved, "Removed"},
		{DiffModified, "Modified"},
		{DiffReordered, "Reordered"},
		{DiffModified | DiffReordered, "Modified|Reordered"},
		{0, "Unchanged"},
	}
	for _, tc := range tests {
		if got := tc.dt.String(); got != tc.want {
			t.Errorf("DiffType(%d).String() = %q, want %q", tc.dt, got, tc.want)
		}
	}
}
