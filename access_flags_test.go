package gontsd

import "testing"

func TestAccessMask_Names_Single(t *testing.T) {
	names := RIGHT_DS_CREATE_CHILD.Names()
	if len(names) != 1 {
		t.Fatalf("Names() returned %d flags, want 1", len(names))
	}
	if names[0] != "RIGHT_DS_CREATE_CHILD" {
		t.Errorf("Names() = %v, want [RIGHT_DS_CREATE_CHILD]", names)
	}
}

func TestAccessMask_Names_Multiple(t *testing.T) {
	mask := RIGHT_DS_READ_PROPERTY | RIGHT_DS_WRITE_PROPERTY
	names := mask.Names()
	if len(names) != 2 {
		t.Fatalf("Names() returned %d flags, want 2", len(names))
	}
	found := make(map[string]bool)
	for _, f := range names {
		found[f] = true
	}
	if !found["RIGHT_DS_READ_PROPERTY"] || !found["RIGHT_DS_WRITE_PROPERTY"] {
		t.Errorf("Names() = %v, want RIGHT_DS_READ_PROPERTY and RIGHT_DS_WRITE_PROPERTY", names)
	}
}

func TestAccessMask_Names_Zero(t *testing.T) {
	names := AccessMask(0).Names()
	if len(names) != 0 {
		t.Errorf("Names() = %v, want empty", names)
	}
}

func TestAccessMask_Names_GenericAll(t *testing.T) {
	names := RIGHT_GENERIC_ALL.Names()
	if len(names) != 1 {
		t.Fatalf("Names() returned %d flags, want 1", len(names))
	}
	if names[0] != "RIGHT_GENERIC_ALL" {
		t.Errorf("Names() = %v, want [RIGHT_GENERIC_ALL]", names)
	}
}

func TestAccessMask_Has(t *testing.T) {
	mask := RIGHT_DS_READ_PROPERTY | RIGHT_DS_WRITE_PROPERTY
	if !mask.Has(RIGHT_DS_READ_PROPERTY) {
		t.Error("Has(RIGHT_DS_READ_PROPERTY) should be true")
	}
	if mask.Has(RIGHT_DELETE) {
		t.Error("Has(RIGHT_DELETE) should be false")
	}
}

func TestAccessMask_String(t *testing.T) {
	mask := RIGHT_DS_READ_PROPERTY | RIGHT_DS_WRITE_PROPERTY
	s := mask.String()
	if s != "RIGHT_DS_READ_PROPERTY|RIGHT_DS_WRITE_PROPERTY" {
		t.Errorf("String() = %q, want %q", s, "RIGHT_DS_READ_PROPERTY|RIGHT_DS_WRITE_PROPERTY")
	}
}

func TestAccessMask_String_Zero(t *testing.T) {
	s := AccessMask(0).String()
	if s != "0x00000000" {
		t.Errorf("String() = %q, want %q", s, "0x00000000")
	}
}
