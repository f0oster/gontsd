package gontsd

import "testing"

func TestGuidStringToBinaryFilter(t *testing.T) {
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
