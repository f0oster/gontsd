package gontsd

import (
	"os"
	"path/filepath"
	"testing"
)

func loadTestData(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("examples", "test_cases", path))
	if err != nil {
		t.Fatalf("failed to read test data %s: %v", path, err)
	}
	return data
}

func TestParse_AddingNewUser(t *testing.T) {
	tests := []struct {
		name     string
		file     string
		aceCount int
		ownerSID string
		groupSID string
	}{
		{
			name:     "default",
			file:     "adding_new_user/sd-filedomain_default.bin",
			aceCount: 4,
			ownerSID: "S-1-5-21-75115020-4145467708-3593911600-1612",
			groupSID: "S-1-5-21-75115020-4145467708-3593911600-513",
		},
		{
			name:     "change",
			file:     "adding_new_user/sd-filedomain_change.bin",
			aceCount: 5,
			ownerSID: "S-1-5-21-75115020-4145467708-3593911600-1612",
			groupSID: "S-1-5-21-75115020-4145467708-3593911600-513",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := loadTestData(t, tc.file)
			sd, err := Parse(data, nil)
			if err != nil {
				t.Fatalf("Parse() error: %v", err)
			}
			if sd.Revision != 1 {
				t.Errorf("Revision = %d, want 1", sd.Revision)
			}
			if sd.ControlFlags != 0x8404 {
				t.Errorf("ControlFlags = 0x%04X, want 0x8404", sd.ControlFlags)
			}
			if sd.OwnerSID == nil || sd.OwnerSID.Parsed != tc.ownerSID {
				t.Errorf("OwnerSID = %v, want %s", sd.OwnerSID, tc.ownerSID)
			}
			if sd.GroupSID == nil || sd.GroupSID.Parsed != tc.groupSID {
				t.Errorf("GroupSID = %v, want %s", sd.GroupSID, tc.groupSID)
			}
			if sd.DACL == nil {
				t.Fatal("DACL is nil")
			}
			if len(sd.DACL.ACEs) != tc.aceCount {
				t.Errorf("DACL ACE count = %d, want %d", len(sd.DACL.ACEs), tc.aceCount)
			}
		})
	}
}

func TestParse_FlagChanges(t *testing.T) {
	tests := []struct {
		name     string
		file     string
		ace0Mask AccessMask
	}{
		{
			name:     "removing_flag/default",
			file:     "removing_flag/sd-filedomain_default.bin",
			ace0Mask: 0x001301BF,
		},
		{
			name:     "removing_flag/change",
			file:     "removing_flag/sd-filedomain_change.bin",
			ace0Mask: 0x001200A9,
		},
		{
			name:     "adding_flag/default",
			file:     "adding_flag/sd-filedomain_default.bin",
			ace0Mask: 0x001200A9,
		},
		{
			name:     "adding_flag/change",
			file:     "adding_flag/sd-filedomain_change.bin",
			ace0Mask: 0x001301BF,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := loadTestData(t, tc.file)
			sd, err := Parse(data, nil)
			if err != nil {
				t.Fatalf("Parse() error: %v", err)
			}
			if sd.DACL == nil || len(sd.DACL.ACEs) == 0 {
				t.Fatal("DACL is nil or empty")
			}
			if sd.DACL.ACEs[0].Mask() != tc.ace0Mask {
				t.Errorf("ACE[0] mask = %s, want %s", sd.DACL.ACEs[0].Mask(), tc.ace0Mask)
			}
		})
	}
}

func TestParse_RootDomain(t *testing.T) {
	data := loadTestData(t, "root_domain/sd-domainroot.bin")
	sd, err := Parse(data, nil)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if sd.Revision != 1 {
		t.Errorf("Revision = %d, want 1", sd.Revision)
	}
	if sd.OwnerSID == nil || sd.OwnerSID.Parsed != "S-1-5-32-544" {
		t.Errorf("OwnerSID = %v, want S-1-5-32-544", sd.OwnerSID)
	}
	if sd.DACL == nil {
		t.Fatal("DACL is nil")
	}
	if len(sd.DACL.ACEs) != 58 {
		t.Errorf("DACL ACE count = %d, want 58", len(sd.DACL.ACEs))
	}
	// First ACE is a deny ACE
	if sd.DACL.ACEs[0].Type() != AccessDeniedACEType {
		t.Errorf("ACE[0] type = 0x%02X, want 0x%02X", sd.DACL.ACEs[0].Type(), AccessDeniedACEType)
	}
	// Verify mix of ACE types: simple and object
	if sd.DACL.ACEs[11].Type() != AccessAllowedObjectACEType {
		t.Errorf("ACE[11] type = 0x%02X, want 0x%02X", sd.DACL.ACEs[11].Type(), AccessAllowedObjectACEType)
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
	// 20-byte descriptor with all offsets = 0 (no owner, group, DACL, SACL)
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
	data := loadTestData(t, "adding_new_user/sd-filedomain_default.bin")
	sd, err := Parse(data, nil)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	sids := sd.CollectSIDs()

	// Owner + group + 4 ACE SIDs, but owner SID matches ACE[3] SID and
	// group SID is unique, so expect 5 unique SIDs.
	if len(sids) != 5 {
		t.Errorf("CollectSIDs() returned %d SIDs, want 5", len(sids))
	}

	// Check deduplication — no SID string should appear twice.
	seen := make(map[string]bool)
	for _, sid := range sids {
		if seen[sid.Parsed] {
			t.Errorf("duplicate SID: %s", sid.Parsed)
		}
		seen[sid.Parsed] = true
	}

	// Owner and group should be included.
	if !seen[sd.OwnerSID.Parsed] {
		t.Error("OwnerSID not in CollectSIDs result")
	}
	if !seen[sd.GroupSID.Parsed] {
		t.Error("GroupSID not in CollectSIDs result")
	}
}

func TestCollectSIDs_Nil(t *testing.T) {
	var sd *SecurityDescriptor
	if sids := sd.CollectSIDs(); sids != nil {
		t.Errorf("nil SD.CollectSIDs() = %v, want nil", sids)
	}
}
