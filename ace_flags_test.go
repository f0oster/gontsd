package gontsd

import "testing"

func TestACEFlags_Names_Single(t *testing.T) {
	names := INHERITED_ACE.Names()
	if len(names) != 1 || names[0] != "INHERITED_ACE" {
		t.Errorf("Names() = %v, want [INHERITED_ACE]", names)
	}
}

func TestACEFlags_Names_Multiple(t *testing.T) {
	flags := OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERITED_ACE
	names := flags.Names()
	if len(names) != 3 {
		t.Fatalf("Names() returned %d flags, want 3", len(names))
	}
	want := map[string]bool{
		"OBJECT_INHERIT_ACE":    true,
		"CONTAINER_INHERIT_ACE": true,
		"INHERITED_ACE":         true,
	}
	for _, f := range names {
		if !want[f] {
			t.Errorf("unexpected flag: %s", f)
		}
	}
}

func TestACEFlags_Names_Zero(t *testing.T) {
	names := ACEFlags(0).Names()
	if len(names) != 0 {
		t.Errorf("Names() = %v, want empty", names)
	}
}

func TestACEFlags_Names_AuditFlags(t *testing.T) {
	flags := SUCCESSFUL_ACCESS_ACE_FLAG | FAILED_ACCESS_ACE_FLAG
	names := flags.Names()
	if len(names) != 2 {
		t.Fatalf("Names() returned %d flags, want 2", len(names))
	}
}

func TestACEFlags_Has(t *testing.T) {
	flags := OBJECT_INHERIT_ACE | INHERITED_ACE
	if !flags.Has(INHERITED_ACE) {
		t.Error("Has(INHERITED_ACE) should be true")
	}
	if flags.Has(CONTAINER_INHERIT_ACE) {
		t.Error("Has(CONTAINER_INHERIT_ACE) should be false")
	}
}

func TestACEFlags_String(t *testing.T) {
	t.Run("Single", func(t *testing.T) {
		s := INHERITED_ACE.String()
		if s != "INHERITED_ACE" {
			t.Errorf("String() = %q, want INHERITED_ACE", s)
		}
	})

	t.Run("Multiple", func(t *testing.T) {
		s := (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE).String()
		if s != "OBJECT_INHERIT_ACE|CONTAINER_INHERIT_ACE" {
			t.Errorf("String() = %q, want OBJECT_INHERIT_ACE|CONTAINER_INHERIT_ACE", s)
		}
	})

	t.Run("Zero", func(t *testing.T) {
		s := ACEFlags(0).String()
		if s != "0x00" {
			t.Errorf("String() = %q, want 0x00", s)
		}
	})
}
