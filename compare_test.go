package gontsd

import (
	"testing"
)

func TestCompare_AddingNewUser(t *testing.T) {
	defaultData := loadTestData(t, "adding_new_user/sd-filedomain_default.bin")
	changeData := loadTestData(t, "adding_new_user/sd-filedomain_change.bin")

	defaultSD, err := Parse(defaultData)
	if err != nil {
		t.Fatalf("Parse default: %v", err)
	}
	changeSD, err := Parse(changeData)
	if err != nil {
		t.Fatalf("Parse change: %v", err)
	}

	diff := Compare(defaultSD, changeSD)
	if !diff.HasChanges() {
		t.Fatal("expected changes, got none")
	}
	if diff.OwnerChanged {
		t.Error("owner should not have changed")
	}
	if diff.GroupChanged {
		t.Error("group should not have changed")
	}
	if diff.DACLDiff == nil {
		t.Fatal("DACLDiff is nil, expected changes")
	}

	// Should have an added ACE
	var foundAdded bool
	for _, d := range diff.DACLDiff.ACEDiffs {
		if d.Type.Has(DiffAdded) {
			foundAdded = true
			if d.NewACE.GetSID().Parsed != "S-1-5-21-75115020-4145467708-3593911600-1627" {
				t.Errorf("added ACE SID = %s, want ...1627", d.NewACE.GetSID().Parsed)
			}
		}
	}
	if !foundAdded {
		t.Error("expected a DiffAdded entry in DACLDiff")
	}
}

func TestCompare_RemovingFlag(t *testing.T) {
	defaultData := loadTestData(t, "removing_flag/sd-filedomain_default.bin")
	changeData := loadTestData(t, "removing_flag/sd-filedomain_change.bin")

	defaultSD, err := Parse(defaultData)
	if err != nil {
		t.Fatalf("Parse default: %v", err)
	}
	changeSD, err := Parse(changeData)
	if err != nil {
		t.Fatalf("Parse change: %v", err)
	}

	diff := Compare(defaultSD, changeSD)
	if !diff.HasChanges() {
		t.Fatal("expected changes, got none")
	}
	if diff.DACLDiff == nil {
		t.Fatal("DACLDiff is nil")
	}

	var foundModified bool
	for _, d := range diff.DACLDiff.ACEDiffs {
		if d.Type.Has(DiffModified) {
			foundModified = true
			if d.OldACE.GetMask() == d.NewACE.GetMask() {
				t.Error("modified ACE should have different masks")
			}
		}
	}
	if !foundModified {
		t.Error("expected a DiffModified entry in DACLDiff")
	}
}

func TestCompare_AddingFlag(t *testing.T) {
	defaultData := loadTestData(t, "adding_flag/sd-filedomain_default.bin")
	changeData := loadTestData(t, "adding_flag/sd-filedomain_change.bin")

	defaultSD, err := Parse(defaultData)
	if err != nil {
		t.Fatalf("Parse default: %v", err)
	}
	changeSD, err := Parse(changeData)
	if err != nil {
		t.Fatalf("Parse change: %v", err)
	}

	diff := Compare(defaultSD, changeSD)
	if !diff.HasChanges() {
		t.Fatal("expected changes, got none")
	}
	if diff.DACLDiff == nil {
		t.Fatal("DACLDiff is nil")
	}

	var foundModified bool
	for _, d := range diff.DACLDiff.ACEDiffs {
		if d.Type.Has(DiffModified) {
			foundModified = true
		}
	}
	if !foundModified {
		t.Error("expected a DiffModified entry in DACLDiff")
	}
}

func TestCompare_Identical(t *testing.T) {
	data := loadTestData(t, "adding_new_user/sd-filedomain_default.bin")
	sd, err := Parse(data)
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
	data := loadTestData(t, "adding_new_user/sd-filedomain_default.bin")
	sd, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	diff := Compare(nil, sd)
	if !diff.HasChanges() {
		t.Error("expected changes when old is nil")
	}
}

func TestCompare_NilNew(t *testing.T) {
	data := loadTestData(t, "adding_new_user/sd-filedomain_default.bin")
	sd, err := Parse(data)
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
