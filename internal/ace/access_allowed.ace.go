// internal/ace/access_allowed.go
package ace

import (
	"encoding/binary"
	"fmt"

	"github.com/f0oster/gontsd/internal/accessflags"
	"github.com/f0oster/gontsd/internal/sid"
)

type AccessAllowedACE struct {
	Header ACEHeader
	Mask   uint32
	SID    *sid.SID
	Flags  []string
}

func (a *AccessAllowedACE) Type() uint8  { return a.Header.AceType }
func (a *AccessAllowedACE) Size() uint16 { return a.Header.AceSize }
func (a *AccessAllowedACE) String() string {
	return fmt.Sprintf(`AccessAllowedACE {
  Mask: 0x%08X
  SID:  %s
  Flags: %v
}`, a.Mask, a.SID, a.Flags)
}

func parseAccessAllowedACE(data []byte) (*AccessAllowedACE, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("too short for AccessAllowedACE")
	}

	header := ACEHeader{
		AceType:  data[0],
		AceFlags: data[1],
		AceSize:  binary.LittleEndian.Uint16(data[2:4]),
	}
	mask := binary.LittleEndian.Uint32(data[4:8])

	s, _, err := sid.ParseSID(data[8:])
	if err != nil {
		return nil, err
	}

	return &AccessAllowedACE{
		Header: header,
		Mask:   mask,
		SID:    s,
		Flags:  accessflags.CheckFlags(mask),
	}, nil
}
