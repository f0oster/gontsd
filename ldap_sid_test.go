package gontsd

import (
	"bytes"
	"testing"

)

func TestSIDFromString(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"local system", "S-1-5-18", false},
		{"everyone", "S-1-1-0", false},
		{"domain SID", "S-1-5-21-75115020-4145467708-3593911600-1612", false},
		{"no prefix", "1-5-18", true},
		{"too short", "S-1", true},
		{"bad revision", "S-abc-5-18", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := SIDFromString(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Error("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("SIDFromString() error: %v", err)
			}
			if len(raw) < 8 {
				t.Fatal("raw SID too short")
			}
		})
	}
}

func TestSIDFromString_RoundTrip(t *testing.T) {
	sidStr := "S-1-5-21-75115020-4145467708-3593911600-1612"
	raw, err := SIDFromString(sidStr)
	if err != nil {
		t.Fatalf("SIDFromString() error: %v", err)
	}
	sd, err := Parse(buildMinimalSD(raw), nil)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if sd.OwnerSID == nil || sd.OwnerSID.Value != sidStr {
		t.Errorf("round-trip SID = %v, want %s", sd.OwnerSID, sidStr)
	}
	if !bytes.Equal(sd.OwnerSID.Raw, raw) {
		t.Error("round-trip raw bytes don't match")
	}
}

// buildMinimalSD creates a minimal 20-byte SD header with an owner SID at offset 20.
func buildMinimalSD(ownerSID []byte) []byte {
	buf := make([]byte, 20+len(ownerSID))
	buf[0] = 1
	buf[4] = 20
	copy(buf[20:], ownerSID)
	return buf
}
