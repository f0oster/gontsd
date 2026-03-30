package gontsd

import (
	"encoding/binary"
	"strings"
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

func TestParse_WithResolver(t *testing.T) {
	data := loadFixture(t, "all_ace_types/sd.bin")
	r := NewResolver()
	sd, err := Parse(data, r)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	// Owner SID (S-1-5-18 = Local System) should be resolved.
	resolved := sd.OwnerSID.Resolved()
	if resolved == sd.OwnerSID.Value {
		t.Errorf("OwnerSID.Resolved() = %q, expected resolved name", resolved)
	}
	if !strings.Contains(resolved, "S-1-5-18") {
		t.Errorf("OwnerSID.Resolved() = %q, should contain raw SID", resolved)
	}

	// A well-known SID in the DACL (Everyone = S-1-1-0) should also resolve.
	ace0SID := sd.DACL.ACEs[0].SID()
	if ace0SID.Resolved() == ace0SID.Value {
		t.Errorf("ACE[0] SID.Resolved() = %q, expected resolved name", ace0SID.Resolved())
	}

	// Object type GUIDs should be resolved to names.
	// ACE[5] is AccessAllowedObject with ObjectType=Reset-Password.
	objGUID := sd.DACL.ACEs[5].ObjectTypeGUID()
	if objGUID == nil {
		t.Fatal("ACE[5].ObjectTypeGUID() is nil")
	}
	if objGUID.Name == "" {
		t.Error("ObjectTypeGUID.Name should be populated after resolution")
	}
	if objGUID.Resolved() == objGUID.Raw {
		t.Errorf("ObjectTypeGUID.Resolved() = %q, expected resolved name", objGUID.Resolved())
	}

	// Domain-relative SIDs (S-1-5-21-...) won't resolve with just well-known tables.
	// Verify they fall back gracefully to the raw value.
	for _, ace := range sd.DACL.ACEs {
		sid := ace.SID()
		if sid == nil {
			continue
		}
		r := sid.Resolved()
		if r == "" {
			t.Errorf("SID.Resolved() returned empty for %s", sid.Value)
		}
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

func TestParse_TruncatedACLHeader(t *testing.T) {
	// DACL offset points near the end of the descriptor, leaving less
	// than 8 bytes for the ACL header. This should not panic.
	data := make([]byte, 24)
	data[0] = 1                                              // revision
	binary.LittleEndian.PutUint16(data[2:4], 0x8004)        // SE_DACL_PRESENT | SE_SELF_RELATIVE
	binary.LittleEndian.PutUint32(data[16:20], uint32(23))   // daclOffset = 23, only 1 byte left

	sd, err := Parse(data, nil)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	// DACL should be silently skipped, not panic.
	if sd.DACL != nil {
		t.Error("DACL should be nil when offset leaves insufficient room for ACL header")
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

func TestSecurityDescriptor_String(t *testing.T) {
	data := loadFixture(t, "all_ace_types/sd.bin")
	sd, err := Parse(data, nil)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	s := sd.String()
	if s == "" {
		t.Fatal("String() is empty")
	}
	if !strings.Contains(s, "Security Descriptor:") {
		t.Error("String() should contain header")
	}
	if !strings.Contains(s, "DACL:") {
		t.Error("String() should contain DACL section")
	}
	if !strings.Contains(s, "SACL:") {
		t.Error("String() should contain SACL section")
	}
	if !strings.Contains(s, "S-1-5-18") {
		t.Error("String() should contain owner SID")
	}
}

func TestACL_String(t *testing.T) {
	data := loadFixture(t, "object_aces/sd.bin")
	sd, err := Parse(data, nil)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	s := sd.DACL.String()
	if !strings.Contains(s, "ACL (Revision:") {
		t.Error("ACL.String() should contain header")
	}
	if !strings.Contains(s, "ACE[0]:") {
		t.Error("ACL.String() should contain ACE entries")
	}
}

func TestACL_String_Nil(t *testing.T) {
	var acl *ACL
	if s := acl.String(); s != "<nil>" {
		t.Errorf("nil ACL.String() = %q, want <nil>", s)
	}
}

func TestGUID_Methods(t *testing.T) {
	t.Run("Nil", func(t *testing.T) {
		var g *GUID
		if g.String() != "" {
			t.Error("nil GUID.String() should be empty")
		}
		if g.Resolved() != "" {
			t.Error("nil GUID.Resolved() should be empty")
		}
	})

	t.Run("Unresolved", func(t *testing.T) {
		g := &GUID{Raw: "some-guid"}
		if g.String() != "some-guid" {
			t.Errorf("String() = %q, want some-guid", g.String())
		}
		if g.Resolved() != "some-guid" {
			t.Errorf("Resolved() = %q, want some-guid (fallback)", g.Resolved())
		}
	})

	t.Run("Resolved", func(t *testing.T) {
		g := &GUID{Raw: "some-guid", Name: "Friendly Name"}
		if g.Resolved() != "Friendly Name" {
			t.Errorf("Resolved() = %q, want Friendly Name", g.Resolved())
		}
	})
}

func TestSID_Resolved(t *testing.T) {
	t.Run("Nil", func(t *testing.T) {
		var s *SID
		if s.Resolved() != "<nil>" {
			t.Errorf("nil SID.Resolved() = %q, want <nil>", s.Resolved())
		}
	})

	t.Run("NoResolver", func(t *testing.T) {
		s := &SID{Value: "S-1-5-18"}
		if s.Resolved() != "S-1-5-18" {
			t.Errorf("Resolved() = %q, want raw SID", s.Resolved())
		}
	})
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
