package gontsd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Domain SID and schema GUIDs matching the SDDL in scripts/New-TestFixtures.ps1.
const (
	testDomainSID = "S-1-5-21-1000-2000-3000"

	fixtureGUIDResetPassword  = "00299570-246d-11d0-a768-00aa006e0529"
	fixtureGUIDChangePassword = "ab721a53-1e2f-11d0-9819-00aa0040529b"
	fixtureGUIDPersonalInfo   = "77b5b886-944a-11d1-aebd-0000f80367c1"
	fixtureGUIDDescription    = "bf967950-0de6-11d0-a285-00aa003049e2"
	fixtureGUIDUserClass      = "bf967aba-0de6-11d0-a285-00aa003049e2"
	fixtureGUIDComputerClass  = "bf967a86-0de6-11d0-a285-00aa003049e2"
	fixtureGUIDMember         = "bf9679c0-0de6-11d0-a285-00aa003049e2"
)

func loadFixture(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", path))
	if err != nil {
		t.Fatalf("failed to read fixture %s: %v", path, err)
	}
	return data
}

func guidEquals(g *GUID, expected string) bool {
	if g == nil {
		return false
	}
	return strings.EqualFold(g.Raw, expected)
}

// ---------------------------------------------------------------------------
// object_aces — simple and object ACEs with all GUID flag combinations
// ---------------------------------------------------------------------------

func TestFixture_ObjectACEs(t *testing.T) {
	data := loadFixture(t, "object_aces/sd.bin")
	sd, err := Parse(data, nil)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	if sd.DACL == nil {
		t.Fatal("DACL is nil")
	}
	if len(sd.DACL.ACEs) != 7 {
		t.Fatalf("DACL ACE count = %d, want 7", len(sd.DACL.ACEs))
	}

	aces := sd.DACL.ACEs

	// [0] AccessDenied, Everyone, Delete
	t.Run("AccessDenied", func(t *testing.T) {
		a := aces[0]
		if a.Type() != AccessDeniedACEType {
			t.Errorf("Type = %v, want AccessDenied", a.Type())
		}
		if _, ok := a.(*AccessDeniedACE); !ok {
			t.Errorf("type assert: got %T, want *AccessDeniedACE", a)
		}
		if a.SID() == nil || a.SID().Value != "S-1-1-0" {
			t.Errorf("SID = %v, want S-1-1-0", a.SID())
		}
		if !a.Mask().Has(RIGHT_DELETE) {
			t.Errorf("Mask = %s, want DELETE set", a.Mask())
		}
		if a.ObjectTypeGUID() != nil {
			t.Error("ObjectTypeGUID should be nil")
		}
		if a.InheritedObjectTypeGUID() != nil {
			t.Error("InheritedObjectTypeGUID should be nil")
		}
	})

	// [1] AccessDeniedObject, Everyone, ObjectType=Change-Password (flags=0x01)
	t.Run("DeniedObject_ObjectTypeOnly", func(t *testing.T) {
		a := aces[1]
		if a.Type() != AccessDeniedObjectACEType {
			t.Errorf("Type = %v, want AccessDeniedObject", a.Type())
		}
		if _, ok := a.(*AccessDeniedObjectACE); !ok {
			t.Errorf("type assert: got %T, want *AccessDeniedObjectACE", a)
		}
		if a.SID() == nil || a.SID().Value != "S-1-1-0" {
			t.Errorf("SID = %v, want S-1-1-0", a.SID())
		}
		if !guidEquals(a.ObjectTypeGUID(), fixtureGUIDChangePassword) {
			t.Errorf("ObjectTypeGUID = %v, want %s", a.ObjectTypeGUID(), fixtureGUIDChangePassword)
		}
		if a.InheritedObjectTypeGUID() != nil {
			t.Error("InheritedObjectTypeGUID should be nil")
		}
	})

	// [2] AccessDeniedObject, Domain Users, ObjectType=Member, InheritedObjectType=User (flags=0x03)
	t.Run("DeniedObject_BothGUIDs", func(t *testing.T) {
		a := aces[2]
		if a.Type() != AccessDeniedObjectACEType {
			t.Errorf("Type = %v, want AccessDeniedObject", a.Type())
		}
		if a.SID() == nil || a.SID().Value != testDomainSID+"-513" {
			t.Errorf("SID = %v, want %s", a.SID(), testDomainSID+"-513")
		}
		if !guidEquals(a.ObjectTypeGUID(), fixtureGUIDMember) {
			t.Errorf("ObjectTypeGUID = %v, want %s", a.ObjectTypeGUID(), fixtureGUIDMember)
		}
		if !guidEquals(a.InheritedObjectTypeGUID(), fixtureGUIDUserClass) {
			t.Errorf("InheritedObjectTypeGUID = %v, want %s", a.InheritedObjectTypeGUID(), fixtureGUIDUserClass)
		}
	})

	// [3] AccessAllowed, SYSTEM, GenericAll
	t.Run("AccessAllowed", func(t *testing.T) {
		a := aces[3]
		if a.Type() != AccessAllowedACEType {
			t.Errorf("Type = %v, want AccessAllowed", a.Type())
		}
		if _, ok := a.(*AccessAllowedACE); !ok {
			t.Errorf("type assert: got %T, want *AccessAllowedACE", a)
		}
		if a.SID() == nil || a.SID().Value != "S-1-5-18" {
			t.Errorf("SID = %v, want S-1-5-18", a.SID())
		}
		if !a.Mask().Has(RIGHT_GENERIC_ALL) {
			t.Errorf("Mask = %s, want GENERIC_ALL set", a.Mask())
		}
	})

	// [4] AccessAllowedObject, Auth Users, ObjectType=Reset-Password (flags=0x01)
	t.Run("AllowedObject_ObjectTypeOnly", func(t *testing.T) {
		a := aces[4]
		if a.Type() != AccessAllowedObjectACEType {
			t.Errorf("Type = %v, want AccessAllowedObject", a.Type())
		}
		if _, ok := a.(*AccessAllowedObjectACE); !ok {
			t.Errorf("type assert: got %T, want *AccessAllowedObjectACE", a)
		}
		if a.SID() == nil || a.SID().Value != "S-1-5-11" {
			t.Errorf("SID = %v, want S-1-5-11", a.SID())
		}
		if !guidEquals(a.ObjectTypeGUID(), fixtureGUIDResetPassword) {
			t.Errorf("ObjectTypeGUID = %v, want %s", a.ObjectTypeGUID(), fixtureGUIDResetPassword)
		}
		if a.InheritedObjectTypeGUID() != nil {
			t.Error("InheritedObjectTypeGUID should be nil")
		}
	})

	// [5] AccessAllowedObject, Domain Admins, InheritedObjectType=User (flags=0x02)
	t.Run("AllowedObject_InheritedOnly", func(t *testing.T) {
		a := aces[5]
		if a.Type() != AccessAllowedObjectACEType {
			t.Errorf("Type = %v, want AccessAllowedObject", a.Type())
		}
		if a.SID() == nil || a.SID().Value != testDomainSID+"-512" {
			t.Errorf("SID = %v, want %s", a.SID(), testDomainSID+"-512")
		}
		if a.ObjectTypeGUID() != nil {
			t.Errorf("ObjectTypeGUID = %v, want nil", a.ObjectTypeGUID())
		}
		if !guidEquals(a.InheritedObjectTypeGUID(), fixtureGUIDUserClass) {
			t.Errorf("InheritedObjectTypeGUID = %v, want %s", a.InheritedObjectTypeGUID(), fixtureGUIDUserClass)
		}
	})

	// [6] AccessAllowedObject, Self, ObjectType=Description, InheritedObjectType=Computer (flags=0x03)
	t.Run("AllowedObject_BothGUIDs", func(t *testing.T) {
		a := aces[6]
		if a.Type() != AccessAllowedObjectACEType {
			t.Errorf("Type = %v, want AccessAllowedObject", a.Type())
		}
		if a.SID() == nil || a.SID().Value != "S-1-5-10" {
			t.Errorf("SID = %v, want S-1-5-10", a.SID())
		}
		if !guidEquals(a.ObjectTypeGUID(), fixtureGUIDDescription) {
			t.Errorf("ObjectTypeGUID = %v, want %s", a.ObjectTypeGUID(), fixtureGUIDDescription)
		}
		if !guidEquals(a.InheritedObjectTypeGUID(), fixtureGUIDComputerClass) {
			t.Errorf("InheritedObjectTypeGUID = %v, want %s", a.InheritedObjectTypeGUID(), fixtureGUIDComputerClass)
		}
	})

	// All ACEs should produce non-empty String() output.
	for i, a := range aces {
		if a.String() == "" {
			t.Errorf("ACE[%d].String() is empty", i)
		}
	}
}

// ---------------------------------------------------------------------------
// audit_aces — SACL with SystemAudit and SystemAuditObject ACEs
// ---------------------------------------------------------------------------

func TestFixture_AuditACEs(t *testing.T) {
	data := loadFixture(t, "audit_aces/sd.bin")
	sd, err := Parse(data, nil)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	if sd.DACL == nil || len(sd.DACL.ACEs) != 2 {
		t.Fatalf("DACL ACE count = %v, want 2", len(sd.DACL.ACEs))
	}
	if sd.SACL == nil {
		t.Fatal("SACL is nil")
	}
	if len(sd.SACL.ACEs) != 4 {
		t.Fatalf("SACL ACE count = %d, want 4", len(sd.SACL.ACEs))
	}

	aces := sd.SACL.ACEs

	// [0] SystemAudit, Everyone, SA+FA
	t.Run("SystemAudit_SuccessAndFailure", func(t *testing.T) {
		a := aces[0]
		if a.Type() != SystemAuditACEType {
			t.Errorf("Type = %v, want SystemAudit", a.Type())
		}
		if _, ok := a.(*SystemAuditACE); !ok {
			t.Errorf("type assert: got %T, want *SystemAuditACE", a)
		}
		if a.SID() == nil || a.SID().Value != "S-1-1-0" {
			t.Errorf("SID = %v, want S-1-1-0", a.SID())
		}
		if !a.AceFlags().Has(SUCCESSFUL_ACCESS_ACE_FLAG) {
			t.Error("expected SUCCESSFUL_ACCESS_ACE_FLAG")
		}
		if !a.AceFlags().Has(FAILED_ACCESS_ACE_FLAG) {
			t.Error("expected FAILED_ACCESS_ACE_FLAG")
		}
	})

	// [1] SystemAudit, Auth Users, FA only
	t.Run("SystemAudit_FailureOnly", func(t *testing.T) {
		a := aces[1]
		if a.Type() != SystemAuditACEType {
			t.Errorf("Type = %v, want SystemAudit", a.Type())
		}
		if a.SID() == nil || a.SID().Value != "S-1-5-11" {
			t.Errorf("SID = %v, want S-1-5-11", a.SID())
		}
		if a.AceFlags().Has(SUCCESSFUL_ACCESS_ACE_FLAG) {
			t.Error("SUCCESSFUL_ACCESS_ACE_FLAG should not be set")
		}
		if !a.AceFlags().Has(FAILED_ACCESS_ACE_FLAG) {
			t.Error("expected FAILED_ACCESS_ACE_FLAG")
		}
	})

	// [2] SystemAuditObject, Everyone, SA, ObjectType=Reset-Password
	t.Run("AuditObject_ObjectTypeOnly", func(t *testing.T) {
		a := aces[2]
		if a.Type() != SystemAuditObjectACEType {
			t.Errorf("Type = %v, want SystemAuditObject", a.Type())
		}
		if _, ok := a.(*SystemAuditObjectACE); !ok {
			t.Errorf("type assert: got %T, want *SystemAuditObjectACE", a)
		}
		if a.SID() == nil || a.SID().Value != "S-1-1-0" {
			t.Errorf("SID = %v, want S-1-1-0", a.SID())
		}
		if !a.AceFlags().Has(SUCCESSFUL_ACCESS_ACE_FLAG) {
			t.Error("expected SUCCESSFUL_ACCESS_ACE_FLAG")
		}
		if !guidEquals(a.ObjectTypeGUID(), fixtureGUIDResetPassword) {
			t.Errorf("ObjectTypeGUID = %v, want %s", a.ObjectTypeGUID(), fixtureGUIDResetPassword)
		}
		if a.InheritedObjectTypeGUID() != nil {
			t.Error("InheritedObjectTypeGUID should be nil")
		}
	})

	// [3] SystemAuditObject, Auth Users, SA+FA, ObjectType=Personal-Info, InheritedObjectType=User
	t.Run("AuditObject_BothGUIDs", func(t *testing.T) {
		a := aces[3]
		if a.Type() != SystemAuditObjectACEType {
			t.Errorf("Type = %v, want SystemAuditObject", a.Type())
		}
		if a.SID() == nil || a.SID().Value != "S-1-5-11" {
			t.Errorf("SID = %v, want S-1-5-11", a.SID())
		}
		if !a.AceFlags().Has(SUCCESSFUL_ACCESS_ACE_FLAG) {
			t.Error("expected SUCCESSFUL_ACCESS_ACE_FLAG")
		}
		if !a.AceFlags().Has(FAILED_ACCESS_ACE_FLAG) {
			t.Error("expected FAILED_ACCESS_ACE_FLAG")
		}
		if !guidEquals(a.ObjectTypeGUID(), fixtureGUIDPersonalInfo) {
			t.Errorf("ObjectTypeGUID = %v, want %s", a.ObjectTypeGUID(), fixtureGUIDPersonalInfo)
		}
		if !guidEquals(a.InheritedObjectTypeGUID(), fixtureGUIDUserClass) {
			t.Errorf("InheritedObjectTypeGUID = %v, want %s", a.InheritedObjectTypeGUID(), fixtureGUIDUserClass)
		}
	})
}

// ---------------------------------------------------------------------------
// callback_aces — conditional ACEs with ApplicationData blobs
// ---------------------------------------------------------------------------

func TestFixture_CallbackACEs(t *testing.T) {
	data := loadFixture(t, "callback_aces/sd.bin")
	sd, err := Parse(data, nil)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	if sd.DACL == nil {
		t.Fatal("DACL is nil")
	}
	if len(sd.DACL.ACEs) != 5 {
		t.Fatalf("DACL ACE count = %d, want 5", len(sd.DACL.ACEs))
	}

	aces := sd.DACL.ACEs

	// [0] AccessAllowed, SYSTEM (baseline)
	t.Run("BaselineAllow", func(t *testing.T) {
		if aces[0].Type() != AccessAllowedACEType {
			t.Errorf("ACE[0] Type = %v, want AccessAllowed", aces[0].Type())
		}
	})

	// [1] AccessAllowed, Domain Admins (baseline)
	t.Run("BaselineAllowDA", func(t *testing.T) {
		if aces[1].Type() != AccessAllowedACEType {
			t.Errorf("ACE[1] Type = %v, want AccessAllowed", aces[1].Type())
		}
	})

	// [2] AccessAllowedCallback, Auth Users, ApplicationData present
	t.Run("AllowedCallback", func(t *testing.T) {
		a := aces[2]
		if a.Type() != AccessAllowedCallbackACEType {
			t.Errorf("Type = %v, want AccessAllowedCallback", a.Type())
		}
		if _, ok := a.(*AccessAllowedCallbackACE); !ok {
			t.Errorf("type assert: got %T, want *AccessAllowedCallbackACE", a)
		}
		if a.SID() == nil || a.SID().Value != "S-1-5-11" {
			t.Errorf("SID = %v, want S-1-5-11", a.SID())
		}
		if a.ApplicationData() == nil || len(a.ApplicationData()) == 0 {
			t.Error("ApplicationData should be non-nil and non-empty")
		}
	})

	// [3] AccessDeniedCallback, Everyone, ApplicationData present
	t.Run("DeniedCallback", func(t *testing.T) {
		a := aces[3]
		if a.Type() != AccessDeniedCallbackACEType {
			t.Errorf("Type = %v, want AccessDeniedCallback", a.Type())
		}
		if _, ok := a.(*AccessDeniedCallbackACE); !ok {
			t.Errorf("type assert: got %T, want *AccessDeniedCallbackACE", a)
		}
		if a.SID() == nil || a.SID().Value != "S-1-1-0" {
			t.Errorf("SID = %v, want S-1-1-0", a.SID())
		}
		if a.ApplicationData() == nil || len(a.ApplicationData()) == 0 {
			t.Error("ApplicationData should be non-nil and non-empty")
		}
	})

	// [4] AccessAllowedCallbackObject, Auth Users, ObjectType=Description, ApplicationData present
	t.Run("AllowedCallbackObject", func(t *testing.T) {
		a := aces[4]
		if a.Type() != AccessAllowedCallbackObjectACEType {
			t.Errorf("Type = %v, want AccessAllowedCallbackObject", a.Type())
		}
		if _, ok := a.(*AccessAllowedCallbackObjectACE); !ok {
			t.Errorf("type assert: got %T, want *AccessAllowedCallbackObjectACE", a)
		}
		if a.SID() == nil || a.SID().Value != "S-1-5-11" {
			t.Errorf("SID = %v, want S-1-5-11", a.SID())
		}
		if !guidEquals(a.ObjectTypeGUID(), fixtureGUIDDescription) {
			t.Errorf("ObjectTypeGUID = %v, want %s", a.ObjectTypeGUID(), fixtureGUIDDescription)
		}
		if a.ApplicationData() == nil || len(a.ApplicationData()) == 0 {
			t.Error("ApplicationData should be non-nil and non-empty")
		}
	})

	// Non-callback ACEs should have nil ApplicationData.
	t.Run("NonCallback_NoAppData", func(t *testing.T) {
		if aces[0].ApplicationData() != nil {
			t.Error("simple AccessAllowed ACE should have nil ApplicationData")
		}
	})
}

// ---------------------------------------------------------------------------
// all_ace_types — every producible ACE type on one descriptor
// ---------------------------------------------------------------------------

func TestFixture_AllACETypes(t *testing.T) {
	data := loadFixture(t, "all_ace_types/sd.bin")
	sd, err := Parse(data, nil)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	if sd.DACL == nil {
		t.Fatal("DACL is nil")
	}
	if sd.SACL == nil {
		t.Fatal("SACL is nil")
	}
	if len(sd.DACL.ACEs) != 10 {
		t.Fatalf("DACL ACE count = %d, want 10", len(sd.DACL.ACEs))
	}
	if len(sd.SACL.ACEs) != 3 {
		t.Fatalf("SACL ACE count = %d, want 3", len(sd.SACL.ACEs))
	}

	// All 9 ACE types should be present across DACL + SACL.
	t.Run("AllTypesPresent", func(t *testing.T) {
		seen := make(map[ACEType]bool)
		for _, a := range sd.DACL.ACEs {
			seen[a.Type()] = true
		}
		for _, a := range sd.SACL.ACEs {
			seen[a.Type()] = true
		}

		expected := []ACEType{
			AccessAllowedACEType,
			AccessDeniedACEType,
			SystemAuditACEType,
			AccessAllowedObjectACEType,
			AccessDeniedObjectACEType,
			SystemAuditObjectACEType,
			AccessAllowedCallbackACEType,
			AccessDeniedCallbackACEType,
			AccessAllowedCallbackObjectACEType,
		}
		for _, typ := range expected {
			if !seen[typ] {
				t.Errorf("missing ACE type %v", typ)
			}
		}
	})

	// Every ACE should have non-empty String() and non-zero Size().
	t.Run("StringAndSize", func(t *testing.T) {
		all := append(sd.DACL.ACEs[:len(sd.DACL.ACEs):len(sd.DACL.ACEs)], sd.SACL.ACEs...)
		for i, a := range all {
			if a.String() == "" {
				t.Errorf("ACE[%d].String() is empty", i)
			}
			if a.Size() == 0 {
				t.Errorf("ACE[%d].Size() is 0", i)
			}
		}
	})
}
