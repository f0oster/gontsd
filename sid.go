package gontsd

import (
	"encoding/binary"
	"fmt"
)

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/78eb9013-1c3a-4970-ad1f-2b1dad588a25
type SID struct {
	Raw          []byte
	Parsed       string
	ResolvedName string
}

func (s *SID) String() string {
	if s == nil {
		return "<nil>"
	}
	return fmt.Sprintf("SID: %s (%s)", s.Parsed, s.ResolvedName)
}

func parseSID(data []byte) (*SID, int, error) {
	if len(data) < 8 {
		return nil, 0, fmt.Errorf("data too short to contain SID header")
	}

	revision := data[0]
	subAuthCount := data[1]

	// SID length = 8 (header) + N * 4
	sidLen := 8 + int(subAuthCount)*4
	if len(data) < sidLen {
		return nil, 0, fmt.Errorf("data too short for full SID: need %d bytes, got %d", sidLen, len(data))
	}

	raw := data[:sidLen]

	// Parse identifier authority (6 bytes big-endian)
	identifierAuthority := uint64(0)
	for i := 2; i < 8; i++ {
		identifierAuthority <<= 8
		identifierAuthority |= uint64(data[i])
	}

	// Parse the sub authorities (each 4 bytes, little-endian)
	subAuthorities := make([]uint32, subAuthCount)
	for i := 0; i < int(subAuthCount); i++ {
		start := 8 + i*4
		subAuthorities[i] = binary.LittleEndian.Uint32(data[start : start+4])
	}

	// Build SID string: S-Revision-IdentifierAuthority-SubAuthority[0]...
	sidStr := fmt.Sprintf("S-%d-%d", revision, identifierAuthority)
	for _, subAuth := range subAuthorities {
		sidStr += fmt.Sprintf("-%d", subAuth)
	}

	// SID resolution is delegated to SIDResolver implementations in the resolve package
	return &SID{
		Raw:    raw,
		Parsed: sidStr,
	}, sidLen, nil
}
