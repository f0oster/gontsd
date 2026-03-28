package gontsd

import (
	"encoding/binary"
	"testing"
)

func buildSimpleACE(aceType uint8, aceFlags uint8, mask uint32, sid []byte) []byte {
	aceSize := uint16(4 + 4 + len(sid)) // header + mask + SID
	buf := make([]byte, aceSize)
	buf[0] = aceType
	buf[1] = aceFlags
	binary.LittleEndian.PutUint16(buf[2:4], aceSize)
	binary.LittleEndian.PutUint32(buf[4:8], mask)
	copy(buf[8:], sid)
	return buf
}

func TestParseACE_AccessAllowed(t *testing.T) {
	sid := buildSIDBinary(1, 5, 18) // S-1-5-18
	data := buildSimpleACE(ACCESS_ALLOWED_ACE_TYPE, 0x00, 0x001F01FF, sid)

	ace, aceLen, err := parseACE(data)
	if err != nil {
		t.Fatalf("parseACE() error: %v", err)
	}
	if aceLen != len(data) {
		t.Errorf("aceLen = %d, want %d", aceLen, len(data))
	}
	if ace.Type() != ACCESS_ALLOWED_ACE_TYPE {
		t.Errorf("Type() = 0x%02X, want 0x%02X", ace.Type(), ACCESS_ALLOWED_ACE_TYPE)
	}
	if ace.GetMask() != 0x001F01FF {
		t.Errorf("GetMask() = 0x%08X, want 0x001F01FF", ace.GetMask())
	}
	if ace.GetSID() == nil || ace.GetSID().Parsed != "S-1-5-18" {
		t.Errorf("GetSID() = %v, want S-1-5-18", ace.GetSID())
	}
	if _, ok := ace.(*AccessAllowedACE); !ok {
		t.Errorf("expected *AccessAllowedACE, got %T", ace)
	}
}

func TestParseACE_AccessDenied(t *testing.T) {
	sid := buildSIDBinary(1, 1, 0) // S-1-1-0
	data := buildSimpleACE(ACCESS_DENIED_ACE_TYPE, 0x00, 0x00000002, sid)

	ace, _, err := parseACE(data)
	if err != nil {
		t.Fatalf("parseACE() error: %v", err)
	}
	if ace.Type() != ACCESS_DENIED_ACE_TYPE {
		t.Errorf("Type() = 0x%02X, want 0x%02X", ace.Type(), ACCESS_DENIED_ACE_TYPE)
	}
	if _, ok := ace.(*AccessDeniedACE); !ok {
		t.Errorf("expected *AccessDeniedACE, got %T", ace)
	}
}

func TestParseACE_UnsupportedType(t *testing.T) {
	sid := buildSIDBinary(1, 5, 18)
	data := buildSimpleACE(0xFF, 0x00, 0x00000000, sid)

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
	if raw.GetSID() != nil {
		t.Error("RawACE.GetSID() should return nil")
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
	data := buildSimpleACE(ACCESS_ALLOWED_ACE_TYPE, 0x00, 0x001F01FF, sid)

	ace, _, err := parseACE(data)
	if err != nil {
		t.Fatalf("parseACE() error: %v", err)
	}
	if g := ace.GetObjectTypeGUID(); g != "" {
		t.Errorf("GetObjectTypeGUID() = %q, want empty for non-object ACE", g)
	}
	if g := ace.GetInheritedObjectTypeGUID(); g != "" {
		t.Errorf("GetInheritedObjectTypeGUID() = %q, want empty for non-object ACE", g)
	}
}

func TestACE_String(t *testing.T) {
	sid := buildSIDBinary(1, 5, 18)
	data := buildSimpleACE(ACCESS_ALLOWED_ACE_TYPE, 0x00, 0x001F01FF, sid)

	ace, _, err := parseACE(data)
	if err != nil {
		t.Fatalf("parseACE() error: %v", err)
	}
	s := ace.String()
	if s == "" {
		t.Error("ACE.String() returned empty string")
	}
}
