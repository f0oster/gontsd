package gontsd

import (
	"encoding/binary"
	"fmt"
	"strings"
)

func indent(s, prefix string) string {
	lines := strings.Split(s, "\n")
	for i := range lines {
		lines[i] = prefix + lines[i]
	}
	return strings.Join(lines, "\n")
}

func guidBytesToString(b []byte) (string, error) {
	if len(b) < 16 {
		return "", fmt.Errorf("want 16 bytes, got %d", len(b))
	}
	d1 := binary.LittleEndian.Uint32(b[0:4])
	d2 := binary.LittleEndian.Uint16(b[4:6])
	d3 := binary.LittleEndian.Uint16(b[6:8])
	// last 8 bytes are already big-endian
	return fmt.Sprintf("%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		d1, d2, d3,
		b[8], b[9],
		b[10], b[11], b[12], b[13], b[14], b[15]), nil
}
