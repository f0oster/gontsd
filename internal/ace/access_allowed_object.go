package ace

import (
	"encoding/binary"
	"fmt"

	"github.com/f0oster/gontsd/internal/accessflags"
	"github.com/f0oster/gontsd/internal/sid"
)

type AccessAllowedObjectACE struct {
	Header              ACEHeader
	Mask                uint32
	Flags               uint32
	ObjectType          [16]byte
	InheritedObjectType [16]byte
	SID                 *sid.SID
	FlagStrings         []string
}

func (a *AccessAllowedObjectACE) Type() uint8  { return a.Header.AceType }
func (a *AccessAllowedObjectACE) Size() uint16 { return a.Header.AceSize }
func (a *AccessAllowedObjectACE) String() string {
	return fmt.Sprintf(`AccessAllowedObjectACE {
  Mask: 0x%08X
  SID:  %s
  Flags %s
}`, a.Mask, a.SID, a.FlagStrings)
}

func parseAccessAllowedObjectACE(data []byte) (*AccessAllowedObjectACE, error) {
	header := ACEHeader{
		AceType:  data[0],
		AceFlags: data[1],
		AceSize:  binary.LittleEndian.Uint16(data[2:4]),
	}
	if len(data) < int(header.AceSize) {
		return nil, fmt.Errorf("ACE claims size %d, but only %d bytes available", header.AceSize, len(data))
	}

	mask := binary.LittleEndian.Uint32(data[4:8])
	flags := binary.LittleEndian.Uint32(data[8:12])

	offset := 12
	var objType, inhType [16]byte

	if flags&0x1 != 0 {
		if offset+16 > len(data) {
			return nil, fmt.Errorf("not enough data for ObjectType")
		}
		copy(objType[:], data[offset:offset+16])
		offset += 16
	}
	if flags&0x2 != 0 {
		if offset+16 > len(data) {
			return nil, fmt.Errorf("not enough data for InheritedObjectType")
		}
		copy(inhType[:], data[offset:offset+16])
		offset += 16
	}

	if offset >= len(data) {
		return nil, fmt.Errorf("not enough data to read SID (offset %d, len %d)", offset, len(data))
	}

	sid, _, err := sid.ParseSID(data[offset:])
	if err != nil {
		return nil, err
	}

	return &AccessAllowedObjectACE{
		Header:              header,
		Mask:                mask,
		Flags:               flags,
		ObjectType:          objType,
		InheritedObjectType: inhType,
		SID:                 sid,
		FlagStrings:         accessflags.CheckFlags(mask),
	}, nil
}
