package gontsd

import "testing"

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
		if got := normalizeGUID(tc.input); got != tc.want {
			t.Errorf("normalizeGUID(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestWellKnownSchemaGUIDResolver(t *testing.T) {
	r := wellKnownSchemaGUIDResolver{}

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
	r := noOpSchemaGUIDResolver{}
	_, err := r.ResolveGUID("anything")
	if err != errSchemaGUIDNotFound {
		t.Errorf("expected errSchemaGUIDNotFound, got %v", err)
	}
}

func TestChainSchemaGUIDResolver(t *testing.T) {
	chain := chainSchemaGUIDResolver{
		Resolvers: []SchemaGUIDResolver{
			noOpSchemaGUIDResolver{},
			wellKnownSchemaGUIDResolver{},
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
