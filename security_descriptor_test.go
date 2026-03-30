package gontsd

import (
	"testing"
)

func TestParse_ObjectACEs_Header(t *testing.T) {
	data := loadFixture(t, "object_aces/sd.bin")
	sd, err := Parse(data, nil)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if sd.Revision != 1 {
		t.Errorf("Revision = %d, want 1", sd.Revision)
	}
	if !sd.ControlFlags.Has(SE_DACL_PRESENT) {
		t.Error("expected SE_DACL_PRESENT")
	}
	if sd.OwnerSID == nil || sd.OwnerSID.Value != "S-1-5-18" {
		t.Errorf("OwnerSID = %v, want S-1-5-18", sd.OwnerSID)
	}
	if sd.GroupSID == nil || sd.GroupSID.Value != "S-1-5-18" {
		t.Errorf("GroupSID = %v, want S-1-5-18", sd.GroupSID)
	}
}

func TestParse_AllACETypes_Header(t *testing.T) {
	data := loadFixture(t, "all_ace_types/sd.bin")
	sd, err := Parse(data, nil)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if sd.Revision != 1 {
		t.Errorf("Revision = %d, want 1", sd.Revision)
	}
	if !sd.ControlFlags.Has(SE_DACL_PRESENT) {
		t.Error("expected SE_DACL_PRESENT")
	}
	if !sd.ControlFlags.Has(SE_SACL_PRESENT) {
		t.Error("expected SE_SACL_PRESENT")
	}
	if sd.DACL == nil {
		t.Fatal("DACL is nil")
	}
	if sd.SACL == nil {
		t.Fatal("SACL is nil")
	}
}

func TestParse_Errors(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"nil data", nil},
		{"empty data", []byte{}},
		{"too short", []byte{0x01, 0x00, 0x04, 0x84}},
		{"exactly 19 bytes", make([]byte, 19)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.data, nil)
			if err == nil {
				t.Error("Parse() expected error, got nil")
			}
		})
	}
}

func TestParse_MinimalValid(t *testing.T) {
	data := make([]byte, 20)
	data[0] = 1 // revision
	sd, err := Parse(data, nil)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if sd.Revision != 1 {
		t.Errorf("Revision = %d, want 1", sd.Revision)
	}
	if sd.OwnerSID != nil {
		t.Error("OwnerSID should be nil for zero offset")
	}
	if sd.DACL != nil {
		t.Error("DACL should be nil for zero offset")
	}
}

func TestSecurityDescriptor_String_Nil(t *testing.T) {
	var sd *SecurityDescriptor
	if s := sd.String(); s != "<nil>" {
		t.Errorf("nil SecurityDescriptor.String() = %q, want %q", s, "<nil>")
	}
}

func TestCollectSIDs(t *testing.T) {
	data := loadFixture(t, "compare_add_ace/after.bin")
	sd, err := Parse(data, nil)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	sids := sd.collectSIDs()

	// Owner (SY) + Group (SY) + ACE SIDs: SY, AU, WD
	// Owner and group are both SY, which also appears in ACE[0].
	// Unique SIDs: S-1-5-18 (SY), S-1-5-11 (AU), S-1-1-0 (WD) = 3
	if len(sids) != 3 {
		t.Errorf("collectSIDs() returned %d SIDs, want 3", len(sids))
	}

	seen := make(map[string]bool)
	for _, sid := range sids {
		if seen[sid.Value] {
			t.Errorf("duplicate SID: %s", sid.Value)
		}
		seen[sid.Value] = true
	}

	if !seen[sd.OwnerSID.Value] {
		t.Error("OwnerSID not in collectSIDs result")
	}
	if !seen[sd.GroupSID.Value] {
		t.Error("GroupSID not in collectSIDs result")
	}
}

func TestCollectSIDs_Nil(t *testing.T) {
	var sd *SecurityDescriptor
	if sids := sd.collectSIDs(); sids != nil {
		t.Errorf("nil SD.collectSIDs() = %v, want nil", sids)
	}
}
