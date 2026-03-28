package gontsd

import "testing"

func TestCheckFlags_SingleFlag(t *testing.T) {
	flags := CheckFlags(RIGHT_DS_CREATE_CHILD)
	if len(flags) != 1 {
		t.Fatalf("CheckFlags(RIGHT_DS_CREATE_CHILD) returned %d flags, want 1", len(flags))
	}
	if flags[0] != "RIGHT_DS_CREATE_CHILD" {
		t.Errorf("CheckFlags(RIGHT_DS_CREATE_CHILD) = %v, want [RIGHT_DS_CREATE_CHILD]", flags)
	}
}

func TestCheckFlags_MultipleFlags(t *testing.T) {
	mask := uint32(RIGHT_DS_READ_PROPERTY | RIGHT_DS_WRITE_PROPERTY)
	flags := CheckFlags(mask)
	if len(flags) != 2 {
		t.Fatalf("CheckFlags(0x%X) returned %d flags, want 2", mask, len(flags))
	}
	found := make(map[string]bool)
	for _, f := range flags {
		found[f] = true
	}
	if !found["RIGHT_DS_READ_PROPERTY"] || !found["RIGHT_DS_WRITE_PROPERTY"] {
		t.Errorf("CheckFlags(0x%X) = %v, want RIGHT_DS_READ_PROPERTY and RIGHT_DS_WRITE_PROPERTY", mask, flags)
	}
}

func TestCheckFlags_Zero(t *testing.T) {
	flags := CheckFlags(0)
	if len(flags) != 0 {
		t.Errorf("CheckFlags(0) = %v, want empty", flags)
	}
}

func TestCheckFlags_GenericAll(t *testing.T) {
	flags := CheckFlags(RIGHT_GENERIC_ALL)
	if len(flags) != 1 {
		t.Fatalf("CheckFlags(RIGHT_GENERIC_ALL) returned %d flags, want 1", len(flags))
	}
	if flags[0] != "RIGHT_GENERIC_ALL" {
		t.Errorf("CheckFlags(RIGHT_GENERIC_ALL) = %v, want [RIGHT_GENERIC_ALL]", flags)
	}
}
