package gontsd

import "testing"

func TestCheckAceFlags_Single(t *testing.T) {
	flags := CheckAceFlags(INHERITED_ACE)
	if len(flags) != 1 || flags[0] != "INHERITED_ACE" {
		t.Errorf("CheckAceFlags(INHERITED_ACE) = %v, want [INHERITED_ACE]", flags)
	}
}

func TestCheckAceFlags_Multiple(t *testing.T) {
	flags := CheckAceFlags(OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERITED_ACE)
	if len(flags) != 3 {
		t.Fatalf("CheckAceFlags() returned %d flags, want 3", len(flags))
	}
	want := map[string]bool{
		"OBJECT_INHERIT_ACE":    true,
		"CONTAINER_INHERIT_ACE": true,
		"INHERITED_ACE":         true,
	}
	for _, f := range flags {
		if !want[f] {
			t.Errorf("unexpected flag: %s", f)
		}
	}
}

func TestCheckAceFlags_Zero(t *testing.T) {
	flags := CheckAceFlags(0)
	if len(flags) != 0 {
		t.Errorf("CheckAceFlags(0) = %v, want empty", flags)
	}
}

func TestCheckAceFlags_AuditFlags(t *testing.T) {
	flags := CheckAceFlags(SUCCESSFUL_ACCESS_ACE_FLAG | FAILED_ACCESS_ACE_FLAG)
	if len(flags) != 2 {
		t.Fatalf("CheckAceFlags() returned %d flags, want 2", len(flags))
	}
}
