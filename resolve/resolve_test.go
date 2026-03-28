package resolve

import (
	"bytes"
	"testing"

	"github.com/f0oster/gontsd"
)

func TestNormalizeGUID(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2", "1131F6AD-9C07-11D1-F79F-00C04FC2DCD2"},
		{"ALREADY-UPPER", "ALREADY-UPPER"},
		{"", ""},
	}
	for _, tc := range tests {
		if got := NormalizeGUID(tc.input); got != tc.want {
			t.Errorf("NormalizeGUID(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestGuidStringToBinaryFilter(t *testing.T) {
	// Known GUID: 1131F6AD-9C07-11D1-F79F-00C04FC2DCD2
	filter, err := guidStringToBinaryFilter("1131F6AD-9C07-11D1-F79F-00C04FC2DCD2")
	if err != nil {
		t.Fatalf("guidStringToBinaryFilter() error: %v", err)
	}
	if filter == "" {
		t.Error("guidStringToBinaryFilter() returned empty string")
	}
	// Should be 16 bytes escaped as \xx each = 48 chars
	if len(filter) != 48 {
		t.Errorf("filter length = %d, want 48", len(filter))
	}
}

func TestGuidStringToBinaryFilter_InvalidLength(t *testing.T) {
	_, err := guidStringToBinaryFilter("too-short")
	if err == nil {
		t.Error("expected error for invalid GUID length")
	}
}

func TestGuidStringToBinaryFilter_InvalidHex(t *testing.T) {
	_, err := guidStringToBinaryFilter("ZZZZZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZZZZZZZZZ")
	if err == nil {
		t.Error("expected error for invalid hex")
	}
}

func TestWellKnownSchemaGUIDResolver(t *testing.T) {
	r := WellKnownSchemaGUIDResolver{}

	info, err := r.ResolveGUID("1131F6AD-9C07-11D1-F79F-00C04FC2DCD2")
	if err != nil {
		t.Fatalf("ResolveGUID() error: %v", err)
	}
	if info.Name != "DS-Replication-Get-Changes-All" {
		t.Errorf("Name = %q, want %q", info.Name, "DS-Replication-Get-Changes-All")
	}

	_, err = r.ResolveGUID("00000000-0000-0000-0000-000000000000")
	if err == nil {
		t.Error("expected error for unknown GUID")
	}
}

func TestNoOpSchemaGUIDResolver(t *testing.T) {
	r := NoOpSchemaGUIDResolver{}
	_, err := r.ResolveGUID("anything")
	if err != ErrSchemaGUIDNotFound {
		t.Errorf("expected ErrSchemaGUIDNotFound, got %v", err)
	}
}

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
	// Build a SID via gontsd.Parse, then convert back via SIDFromString
	// and verify the raw bytes match.
	sidStr := "S-1-5-21-75115020-4145467708-3593911600-1612"
	raw, err := SIDFromString(sidStr)
	if err != nil {
		t.Fatalf("SIDFromString() error: %v", err)
	}
	// Parse the raw bytes back through gontsd to verify
	sd, err := gontsd.Parse(buildMinimalSD(raw))
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if sd.OwnerSID == nil || sd.OwnerSID.Parsed != sidStr {
		t.Errorf("round-trip SID = %v, want %s", sd.OwnerSID, sidStr)
	}
	if !bytes.Equal(sd.OwnerSID.Raw, raw) {
		t.Error("round-trip raw bytes don't match")
	}
}

// buildMinimalSD creates a minimal 20-byte SD header with an owner SID at offset 20.
func buildMinimalSD(ownerSID []byte) []byte {
	buf := make([]byte, 20+len(ownerSID))
	buf[0] = 1 // revision
	// Owner offset = 20 (little-endian at bytes 4-7)
	buf[4] = 20
	copy(buf[20:], ownerSID)
	return buf
}

func TestWellKnownSIDResolver(t *testing.T) {
	r := WellKnownSIDResolver{}

	// Exact match
	name, err := r.Resolve(&gontsd.SID{Parsed: "S-1-5-18"})
	if err != nil {
		t.Fatalf("Resolve(S-1-5-18) error: %v", err)
	}
	if name != "Local System" {
		t.Errorf("Resolve(S-1-5-18) = %q, want %q", name, "Local System")
	}

	// Domain-relative RID matching
	name, err = r.Resolve(&gontsd.SID{Parsed: "S-1-5-21-75115020-4145467708-3593911600-512"})
	if err != nil {
		t.Fatalf("Resolve(domain admin) error: %v", err)
	}
	if name != "Domain Admins" {
		t.Errorf("Resolve(domain admin) = %q, want %q", name, "Domain Admins")
	}

	// Domain-relative RID with different domain identifier
	name, err = r.Resolve(&gontsd.SID{Parsed: "S-1-5-21-999999-888888-777777-500"})
	if err != nil {
		t.Fatalf("Resolve(administrator) error: %v", err)
	}
	if name != "Administrator" {
		t.Errorf("Resolve(administrator) = %q, want %q", name, "Administrator")
	}

	// Unknown domain RID
	_, err = r.Resolve(&gontsd.SID{Parsed: "S-1-5-21-1-2-3-9999"})
	if err == nil {
		t.Error("expected error for unknown domain RID")
	}

	// Nil SID
	_, err = r.Resolve(nil)
	if err == nil {
		t.Error("expected error for nil SID")
	}
}

func TestChainSchemaGUIDResolver(t *testing.T) {
	chain := ChainSchemaGUIDResolver{
		Resolvers: []SchemaGUIDResolver{
			NoOpSchemaGUIDResolver{},
			WellKnownSchemaGUIDResolver{},
		},
	}
	info, err := chain.ResolveGUID("1131F6AD-9C07-11D1-F79F-00C04FC2DCD2")
	if err != nil {
		t.Fatalf("chain.ResolveGUID() error: %v", err)
	}
	if info.Name != "DS-Replication-Get-Changes-All" {
		t.Errorf("Name = %q, want %q", info.Name, "DS-Replication-Get-Changes-All")
	}
}
