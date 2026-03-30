package gontsd

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

func buildSimpleACE(aceType ACEType, aceFlags uint8, mask uint32, sid []byte) []byte {
	aceSize := uint16(4 + 4 + len(sid)) // header + mask + SID
	buf := make([]byte, aceSize)
	buf[0] = uint8(aceType)
	buf[1] = aceFlags
	binary.LittleEndian.PutUint16(buf[2:4], aceSize)
	binary.LittleEndian.PutUint32(buf[4:8], mask)
	copy(buf[8:], sid)
	return buf
}

func TestParseACE_AccessAllowed(t *testing.T) {
	sid := buildSIDBinary(1, 5, 18) // S-1-5-18
	data := buildSimpleACE(AccessAllowedACEType, 0x00, 0x001F01FF, sid)

	ace, aceLen, err := parseACE(data)
	if err != nil {
		t.Fatalf("parseACE() error: %v", err)
	}
	if aceLen != len(data) {
		t.Errorf("aceLen = %d, want %d", aceLen, len(data))
	}
	if ace.Type() != AccessAllowedACEType {
		t.Errorf("Type() = 0x%02X, want 0x%02X", ace.Type(), AccessAllowedACEType)
	}
	if ace.Mask() != 0x001F01FF {
		t.Errorf("Mask() = %s, want 0x001F01FF", ace.Mask())
	}
	if ace.SID() == nil || ace.SID().Value != "S-1-5-18" {
		t.Errorf("GetSID() = %v, want S-1-5-18", ace.SID())
	}
	if _, ok := ace.(*AccessAllowedACE); !ok {
		t.Errorf("expected *AccessAllowedACE, got %T", ace)
	}
}

func TestParseACE_AccessDenied(t *testing.T) {
	sid := buildSIDBinary(1, 1, 0) // S-1-1-0
	data := buildSimpleACE(AccessDeniedACEType, 0x00, 0x00000002, sid)

	ace, _, err := parseACE(data)
	if err != nil {
		t.Fatalf("parseACE() error: %v", err)
	}
	if ace.Type() != AccessDeniedACEType {
		t.Errorf("Type() = 0x%02X, want 0x%02X", ace.Type(), AccessDeniedACEType)
	}
	if _, ok := ace.(*AccessDeniedACE); !ok {
		t.Errorf("expected *AccessDeniedACE, got %T", ace)
	}
}

func TestParseACE_UnsupportedType(t *testing.T) {
	sid := buildSIDBinary(1, 5, 18)
	data := buildSimpleACE(ACEType(0xFF), 0x00, 0x00000000, sid)

	ace, aceLen, err := parseACE(data)
	if err != nil {
		t.Fatalf("parseACE() error: %v", err)
	}
	raw, ok := ace.(*RawACE)
	if !ok {
		t.Fatalf("expected *RawACE, got %T", ace)
	}
	if raw.Type() != 0xFF {
		t.Errorf("Type() = 0x%02X, want 0xFF", raw.Type())
	}
	if aceLen != len(data) {
		t.Errorf("aceLen = %d, want %d", aceLen, len(data))
	}
	// RawACE now parses common fields when possible
	if raw.SID() == nil || raw.SID().Value != "S-1-5-18" {
		t.Errorf("RawACE.SID() = %v, want S-1-5-18", raw.SID())
	}
}

func TestParseACE_TooShort(t *testing.T) {
	_, _, err := parseACE([]byte{0x00, 0x00, 0x04})
	if err == nil {
		t.Error("parseACE() expected error for short data, got nil")
	}
}

func TestACE_NonObjectGUIDs(t *testing.T) {
	sid := buildSIDBinary(1, 5, 18)
	data := buildSimpleACE(AccessAllowedACEType, 0x00, 0x001F01FF, sid)

	ace, _, err := parseACE(data)
	if err != nil {
		t.Fatalf("parseACE() error: %v", err)
	}
	if g := ace.ObjectTypeGUID(); g != nil {
		t.Errorf("ObjectTypeGUID() = %v, want nil for non-object ACE", g)
	}
	if g := ace.InheritedObjectTypeGUID(); g != nil {
		t.Errorf("InheritedObjectTypeGUID() = %v, want nil for non-object ACE", g)
	}
}

func TestACE_String(t *testing.T) {
	sid := buildSIDBinary(1, 5, 18)
	data := buildSimpleACE(AccessAllowedACEType, 0x00, 0x001F01FF, sid)

	ace, _, err := parseACE(data)
	if err != nil {
		t.Fatalf("parseACE() error: %v", err)
	}
	s := ace.String()
	if s == "" {
		t.Error("ACE.String() returned empty string")
	}
}

func TestParseACE_SystemAudit(t *testing.T) {
	sid := buildSIDBinary(1, 1, 0) // Everyone
	data := buildSimpleACE(SystemAuditACEType, 0xC0, 0x00010000, sid)

	ace, _, err := parseACE(data)
	if err != nil {
		t.Fatalf("parseACE() error: %v", err)
	}
	if ace.Type() != SystemAuditACEType {
		t.Errorf("Type = %v, want SystemAudit", ace.Type())
	}
	if _, ok := ace.(*SystemAuditACE); !ok {
		t.Errorf("type assert: got %T, want *SystemAuditACE", ace)
	}
	if !ace.AceFlags().Has(SUCCESSFUL_ACCESS_ACE_FLAG) {
		t.Error("expected SUCCESSFUL_ACCESS_ACE_FLAG")
	}
	if !ace.AceFlags().Has(FAILED_ACCESS_ACE_FLAG) {
		t.Error("expected FAILED_ACCESS_ACE_FLAG")
	}
}

// buildObjectACE constructs a binary object ACE with variable GUID fields.
// objFlags controls which GUIDs are present: 0x01=ObjectType, 0x02=InheritedObjectType.
func buildObjectACE(aceType ACEType, aceFlags uint8, mask uint32, objFlags uint32, objType, inhType [16]byte, sid []byte) []byte {
	size := 12 + len(sid) // header(4) + mask(4) + objFlags(4) + SID
	if objFlags&0x1 != 0 {
		size += 16
	}
	if objFlags&0x2 != 0 {
		size += 16
	}

	buf := make([]byte, size)
	buf[0] = uint8(aceType)
	buf[1] = aceFlags
	binary.LittleEndian.PutUint16(buf[2:4], uint16(size))
	binary.LittleEndian.PutUint32(buf[4:8], mask)
	binary.LittleEndian.PutUint32(buf[8:12], objFlags)

	offset := 12
	if objFlags&0x1 != 0 {
		copy(buf[offset:], objType[:])
		offset += 16
	}
	if objFlags&0x2 != 0 {
		copy(buf[offset:], inhType[:])
		offset += 16
	}
	copy(buf[offset:], sid)
	return buf
}

// buildCallbackObjectACE constructs a binary callback object ACE with GUIDs and appData.
func buildCallbackObjectACE(aceType ACEType, aceFlags uint8, mask uint32, objFlags uint32, objType, inhType [16]byte, sid, appData []byte) []byte {
	base := buildObjectACE(aceType, aceFlags, mask, objFlags, objType, inhType, sid)
	result := make([]byte, len(base)+len(appData))
	copy(result, base)
	copy(result[len(base):], appData)
	// Fix the size field to include appData.
	binary.LittleEndian.PutUint16(result[2:4], uint16(len(result)))
	return result
}

func TestParseACE_ObjectACE(t *testing.T) {
	sid := buildSIDBinary(1, 5, 11) // Auth Users

	// Use recognizable byte patterns for GUIDs.
	var objGUID, inhGUID [16]byte
	for i := range 16 {
		objGUID[i] = byte(0xA0 + i)
		inhGUID[i] = byte(0xB0 + i)
	}
	// guidBytesToString produces a mixed-endian GUID string from these bytes.
	wantObjGUID, _ := guidBytesToString(objGUID[:])
	wantInhGUID, _ := guidBytesToString(inhGUID[:])

	t.Run("ObjectTypeOnly", func(t *testing.T) {
		data := buildObjectACE(AccessAllowedObjectACEType, 0, 0x100, 0x01, objGUID, inhGUID, sid)
		ace, _, err := parseACE(data)
		if err != nil {
			t.Fatalf("parseACE() error: %v", err)
		}
		if ace.ObjectTypeGUID() == nil {
			t.Fatal("ObjectTypeGUID is nil")
		}
		if !strings.EqualFold(ace.ObjectTypeGUID().Raw, wantObjGUID) {
			t.Errorf("ObjectTypeGUID = %s, want %s", ace.ObjectTypeGUID().Raw, wantObjGUID)
		}
		if ace.InheritedObjectTypeGUID() != nil {
			t.Error("InheritedObjectTypeGUID should be nil")
		}
	})

	t.Run("InheritedObjectTypeOnly", func(t *testing.T) {
		data := buildObjectACE(AccessAllowedObjectACEType, 0, 0x100, 0x02, objGUID, inhGUID, sid)
		ace, _, err := parseACE(data)
		if err != nil {
			t.Fatalf("parseACE() error: %v", err)
		}
		if ace.ObjectTypeGUID() != nil {
			t.Error("ObjectTypeGUID should be nil")
		}
		if ace.InheritedObjectTypeGUID() == nil {
			t.Fatal("InheritedObjectTypeGUID is nil")
		}
		if !strings.EqualFold(ace.InheritedObjectTypeGUID().Raw, wantInhGUID) {
			t.Errorf("InheritedObjectTypeGUID = %s, want %s", ace.InheritedObjectTypeGUID().Raw, wantInhGUID)
		}
	})

	t.Run("BothGUIDs", func(t *testing.T) {
		data := buildObjectACE(AccessAllowedObjectACEType, 0, 0x100, 0x03, objGUID, inhGUID, sid)
		ace, _, err := parseACE(data)
		if err != nil {
			t.Fatalf("parseACE() error: %v", err)
		}
		if ace.ObjectTypeGUID() == nil {
			t.Fatal("ObjectTypeGUID is nil")
		}
		if !strings.EqualFold(ace.ObjectTypeGUID().Raw, wantObjGUID) {
			t.Errorf("ObjectTypeGUID = %s, want %s", ace.ObjectTypeGUID().Raw, wantObjGUID)
		}
		if ace.InheritedObjectTypeGUID() == nil {
			t.Fatal("InheritedObjectTypeGUID is nil")
		}
		if !strings.EqualFold(ace.InheritedObjectTypeGUID().Raw, wantInhGUID) {
			t.Errorf("InheritedObjectTypeGUID = %s, want %s", ace.InheritedObjectTypeGUID().Raw, wantInhGUID)
		}
	})
}

func TestParseACE_CallbackACE(t *testing.T) {
	sid := buildSIDBinary(1, 5, 11)
	appData := []byte{0x61, 0x72, 0x74, 0x78, 0x01, 0x02, 0x03} // "artx" magic + data

	// Build callback ACE: header(4) + mask(4) + SID + appData
	aceSize := uint16(4 + 4 + len(sid) + len(appData))
	buf := make([]byte, aceSize)
	buf[0] = uint8(AccessAllowedCallbackACEType)
	buf[1] = 0
	binary.LittleEndian.PutUint16(buf[2:4], aceSize)
	binary.LittleEndian.PutUint32(buf[4:8], 0x10000000)
	copy(buf[8:], sid)
	copy(buf[8+len(sid):], appData)

	ace, _, err := parseACE(buf)
	if err != nil {
		t.Fatalf("parseACE() error: %v", err)
	}
	if ace.Type() != AccessAllowedCallbackACEType {
		t.Errorf("Type = %v, want AccessAllowedCallback", ace.Type())
	}
	if _, ok := ace.(*AccessAllowedCallbackACE); !ok {
		t.Errorf("type assert: got %T, want *AccessAllowedCallbackACE", ace)
	}
	if !bytes.Equal(ace.ApplicationData(), appData) {
		t.Errorf("ApplicationData = %x, want %x", ace.ApplicationData(), appData)
	}
}

func TestParseACE_DeniedCallbackObjectACE(t *testing.T) {
	sid := buildSIDBinary(1, 5, 11)
	appData := []byte{0x61, 0x72, 0x74, 0x78, 0xFF}

	var objGUID [16]byte
	for i := range 16 {
		objGUID[i] = byte(0xC0 + i)
	}
	var noGUID [16]byte

	data := buildCallbackObjectACE(AccessDeniedCallbackObjectACEType, 0, 0x20, 0x01, objGUID, noGUID, sid, appData)

	ace, _, err := parseACE(data)
	if err != nil {
		t.Fatalf("parseACE() error: %v", err)
	}
	if ace.Type() != AccessDeniedCallbackObjectACEType {
		t.Errorf("Type = %v, want AccessDeniedCallbackObject", ace.Type())
	}
	if _, ok := ace.(*AccessDeniedCallbackObjectACE); !ok {
		t.Errorf("type assert: got %T, want *AccessDeniedCallbackObjectACE", ace)
	}
	if ace.ObjectTypeGUID() == nil {
		t.Error("ObjectTypeGUID is nil")
	}
	if !bytes.Equal(ace.ApplicationData(), appData) {
		t.Errorf("ApplicationData = %x, want %x", ace.ApplicationData(), appData)
	}
	if ace.String() == "" {
		t.Error("String() is empty")
	}
}

func TestParseACE_ObjectACE_Errors(t *testing.T) {
	sid := buildSIDBinary(1, 5, 18)
	var guid [16]byte

	t.Run("TruncatedObjectType", func(t *testing.T) {
		data := buildObjectACE(AccessAllowedObjectACEType, 0, 0, 0x01, guid, guid, sid)
		// Truncate so ObjectType GUID is incomplete.
		_, _, err := parseACE(data[:20])
		if err == nil {
			t.Error("expected error for truncated ObjectType")
		}
	})

	t.Run("TruncatedInheritedObjectType", func(t *testing.T) {
		data := buildObjectACE(AccessAllowedObjectACEType, 0, 0, 0x03, guid, guid, sid)
		// Truncate after ObjectType but before InheritedObjectType is complete.
		_, _, err := parseACE(data[:30])
		if err == nil {
			t.Error("expected error for truncated InheritedObjectType")
		}
	})

	t.Run("TruncatedSID", func(t *testing.T) {
		data := buildObjectACE(AccessAllowedObjectACEType, 0, 0, 0x01, guid, guid, sid)
		// Truncate right after the GUID, leaving no room for SID.
		_, _, err := parseACE(data[:28])
		if err == nil {
			t.Error("expected error for truncated SID")
		}
	})

	t.Run("SizeLargerThanData", func(t *testing.T) {
		data := buildObjectACE(AccessAllowedObjectACEType, 0, 0, 0x01, guid, guid, sid)
		// Inflate the declared size beyond actual data.
		binary.LittleEndian.PutUint16(data[2:4], uint16(len(data)+100))
		_, _, err := parseACE(data)
		if err == nil {
			t.Error("expected error for size > data")
		}
	})
}

func TestParseACE_CallbackACE_Errors(t *testing.T) {
	sid := buildSIDBinary(1, 5, 18)
	appData := []byte{0x01, 0x02}

	t.Run("SizeLargerThanData", func(t *testing.T) {
		aceSize := uint16(4 + 4 + len(sid) + len(appData))
		buf := make([]byte, aceSize)
		buf[0] = uint8(AccessAllowedCallbackACEType)
		binary.LittleEndian.PutUint16(buf[2:4], aceSize+50) // inflated size
		binary.LittleEndian.PutUint32(buf[4:8], 0x100)
		copy(buf[8:], sid)
		copy(buf[8+len(sid):], appData)

		_, _, err := parseACE(buf)
		if err == nil {
			t.Error("expected error for size > data")
		}
	})

	t.Run("CallbackObject_SizeLargerThanData", func(t *testing.T) {
		var objGUID, noGUID [16]byte
		data := buildCallbackObjectACE(AccessAllowedCallbackObjectACEType, 0, 0x20, 0x01, objGUID, noGUID, sid, appData)
		// Inflate declared size.
		binary.LittleEndian.PutUint16(data[2:4], uint16(len(data)+50))
		_, _, err := parseACE(data)
		if err == nil {
			t.Error("expected error for size > data")
		}
	})

	t.Run("CallbackObject_TruncatedGUID", func(t *testing.T) {
		var objGUID, noGUID [16]byte
		data := buildCallbackObjectACE(AccessAllowedCallbackObjectACEType, 0, 0x20, 0x01, objGUID, noGUID, sid, appData)
		_, _, err := parseACE(data[:20])
		if err == nil {
			t.Error("expected error for truncated GUID in callback object ACE")
		}
	})
}

func TestACEType_String(t *testing.T) {
	tests := []struct {
		typ  ACEType
		want string
	}{
		{AccessAllowedACEType, "AccessAllowed"},
		{AccessDeniedACEType, "AccessDenied"},
		{SystemAuditACEType, "SystemAudit"},
		{AccessAllowedObjectACEType, "AccessAllowedObject"},
		{AccessDeniedObjectACEType, "AccessDeniedObject"},
		{SystemAuditObjectACEType, "SystemAuditObject"},
		{AccessAllowedCallbackACEType, "AccessAllowedCallback"},
		{AccessDeniedCallbackACEType, "AccessDeniedCallback"},
		{AccessAllowedCallbackObjectACEType, "AccessAllowedCallbackObject"},
		{AccessDeniedCallbackObjectACEType, "AccessDeniedCallbackObject"},
		{ACEType(0xFF), "Unknown(0xFF)"},
	}
	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			got := tc.typ.String()
			if got != tc.want {
				t.Errorf("ACEType(0x%02X).String() = %q, want %q", uint8(tc.typ), got, tc.want)
			}
		})
	}
}

func TestRawACE_Fields(t *testing.T) {
	sid := buildSIDBinary(1, 5, 18)
	data := buildSimpleACE(ACEType(0xFE), 0x00, 0x00000001, sid)

	ace, _, err := parseACE(data)
	if err != nil {
		t.Fatalf("parseACE() error: %v", err)
	}
	raw, ok := ace.(*RawACE)
	if !ok {
		t.Fatalf("expected *RawACE, got %T", ace)
	}
	if raw.ApplicationData() != nil {
		t.Error("RawACE.ApplicationData() should be nil")
	}
	if raw.RawData == nil || len(raw.RawData) == 0 {
		t.Error("RawACE.RawData should be populated")
	}
	s := raw.String()
	if s == "" {
		t.Error("RawACE.String() is empty")
	}
	if !strings.Contains(s, fmt.Sprintf("0x%02X", 0xFE)) {
		t.Errorf("RawACE.String() = %q, expected to contain type hex", s)
	}
}
