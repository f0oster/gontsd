package gontsd

import (
	"encoding/binary"
	"testing"
)

func buildSIDBinary(revision uint8, identifierAuthority uint64, subAuthorities ...uint32) []byte {
	buf := make([]byte, 8+len(subAuthorities)*4)
	buf[0] = revision
	buf[1] = uint8(len(subAuthorities))
	for i := range 6 {
		buf[7-i] = uint8(identifierAuthority >> (8 * i))
	}
	for i, sa := range subAuthorities {
		binary.LittleEndian.PutUint32(buf[8+i*4:], sa)
	}
	return buf
}

func TestParseSID(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		wantSID  string
		wantLen  int
	}{
		{
			name:    "Local System S-1-5-18",
			data:    buildSIDBinary(1, 5, 18),
			wantSID: "S-1-5-18",
			wantLen: 12,
		},
		{
			name:    "Everyone S-1-1-0",
			data:    buildSIDBinary(1, 1, 0),
			wantSID: "S-1-1-0",
			wantLen: 12,
		},
		{
			name:    "Builtin Administrators S-1-5-32-544",
			data:    buildSIDBinary(1, 5, 32, 544),
			wantSID: "S-1-5-32-544",
			wantLen: 16,
		},
		{
			name:    "Domain SID with multiple sub-authorities",
			data:    buildSIDBinary(1, 5, 21, 75115020, 4145467708, 3593911600, 1612),
			wantSID: "S-1-5-21-75115020-4145467708-3593911600-1612",
			wantLen: 28,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sid, sidLen, err := parseSID(tc.data)
			if err != nil {
				t.Fatalf("parseSID() error: %v", err)
			}
			if sid.Parsed != tc.wantSID {
				t.Errorf("parseSID().Parsed = %q, want %q", sid.Parsed, tc.wantSID)
			}
			if sidLen != tc.wantLen {
				t.Errorf("parseSID() length = %d, want %d", sidLen, tc.wantLen)
			}
			if len(sid.Raw) != tc.wantLen {
				t.Errorf("parseSID().Raw length = %d, want %d", len(sid.Raw), tc.wantLen)
			}
		})
	}
}

func TestParseSID_Errors(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"nil", nil},
		{"too short", []byte{1, 2, 3}},
		{"sub-authority count exceeds data", buildSIDBinary(1, 5, 18)[:10]}, // claims 1 sub-auth but truncated
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := parseSID(tc.data)
			if err == nil {
				t.Error("parseSID() expected error, got nil")
			}
		})
	}
}

func TestSID_String(t *testing.T) {
	sid := &SID{Parsed: "S-1-5-18", ResolvedName: "Local System"}
	s := sid.String()
	if s != "SID: S-1-5-18 (Local System)" {
		t.Errorf("SID.String() = %q, want %q", s, "SID: S-1-5-18 (Local System)")
	}

	var nilSID *SID
	if s := nilSID.String(); s != "<nil>" {
		t.Errorf("nil SID.String() = %q, want %q", s, "<nil>")
	}
}
