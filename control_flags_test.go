package gontsd

import (
	"testing"
)

func TestControlFlags_Has(t *testing.T) {
	f := SE_DACL_PRESENT | SE_SELF_RELATIVE
	if !f.Has(SE_DACL_PRESENT) {
		t.Error("expected SE_DACL_PRESENT")
	}
	if !f.Has(SE_SELF_RELATIVE) {
		t.Error("expected SE_SELF_RELATIVE")
	}
	if f.Has(SE_SACL_PRESENT) {
		t.Error("SE_SACL_PRESENT should not be set")
	}
}

func TestControlFlags_Names(t *testing.T) {
	t.Run("Single", func(t *testing.T) {
		names := SE_DACL_PRESENT.Names()
		if len(names) != 1 || names[0] != "SE_DACL_PRESENT" {
			t.Errorf("Names() = %v, want [SE_DACL_PRESENT]", names)
		}
	})

	t.Run("Multiple", func(t *testing.T) {
		f := SE_DACL_PRESENT | SE_SACL_PRESENT | SE_SELF_RELATIVE
		names := f.Names()
		if len(names) != 3 {
			t.Errorf("Names() returned %d names, want 3", len(names))
		}
	})

	t.Run("Zero", func(t *testing.T) {
		names := ControlFlags(0).Names()
		if len(names) != 0 {
			t.Errorf("Names() = %v, want empty", names)
		}
	})
}

func TestControlFlags_String(t *testing.T) {
	t.Run("Single", func(t *testing.T) {
		s := SE_DACL_PRESENT.String()
		if s != "SE_DACL_PRESENT" {
			t.Errorf("String() = %q, want SE_DACL_PRESENT", s)
		}
	})

	t.Run("Multiple", func(t *testing.T) {
		f := SE_DACL_PRESENT | SE_SELF_RELATIVE
		s := f.String()
		if s != "SE_DACL_PRESENT|SE_SELF_RELATIVE" {
			t.Errorf("String() = %q, want SE_DACL_PRESENT|SE_SELF_RELATIVE", s)
		}
	})

	t.Run("Zero", func(t *testing.T) {
		s := ControlFlags(0).String()
		if s != "0x0000" {
			t.Errorf("String() = %q, want 0x0000", s)
		}
	})
}
