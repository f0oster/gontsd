package gontsd

import "testing"

func TestGuidBytesToString(t *testing.T) {
	// GUID: 1131F6AD-9C07-11D1-F79F-00C04FC2DCD2
	// Mixed-endian: first 3 groups are little-endian, last 2 are big-endian
	b := []byte{
		0xAD, 0xF6, 0x31, 0x11, // 1131F6AD (LE)
		0x07, 0x9C,             // 9C07 (LE)
		0xD1, 0x11,             // 11D1 (LE)
		0xF7, 0x9F,             // F79F (BE)
		0x00, 0xC0, 0x4F, 0xC2, 0xDC, 0xD2, // 00C04FC2DCD2 (BE)
	}

	got, err := GUIDBytesToString(b)
	if err != nil {
		t.Fatalf("GUIDBytesToString() error: %v", err)
	}
	want := "1131F6AD-9C07-11D1-F79F-00C04FC2DCD2"
	if got != want {
		t.Errorf("GUIDBytesToString() = %q, want %q", got, want)
	}
}

func TestGuidBytesToString_TooShort(t *testing.T) {
	_, err := GUIDBytesToString([]byte{0x01, 0x02, 0x03})
	if err == nil {
		t.Error("GUIDBytesToString() expected error for short input, got nil")
	}
}

func TestIndent(t *testing.T) {
	input := "line1\nline2\nline3"
	got := indent(input, "  ")
	want := "  line1\n  line2\n  line3"
	if got != want {
		t.Errorf("indent() = %q, want %q", got, want)
	}
}
