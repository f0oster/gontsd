package ace

import (
	"encoding/binary"
	"fmt"

	"github.com/f0oster/gontsd/internal/sid"
)

type SystemMandatoryLabelACE struct {
	Header ACEHeader
	Mask   uint32
	SID    *sid.SID
	Attr   uint32
}

func (a *SystemMandatoryLabelACE) Type() uint8  { return a.Header.AceType }
func (a *SystemMandatoryLabelACE) Size() uint16 { return a.Header.AceSize }
func (a *SystemMandatoryLabelACE) String() string {
	return fmt.Sprintf(`SystemMandatoryLabelACE {
  Mask: 0x%08X
  SID:  %s
  Attr: 0x%08X
}`, a.Mask, a.SID, a.Attr)
}

func parseSystemMandatoryLabelACE(data []byte) (*SystemMandatoryLabelACE, error) {
	header := ACEHeader{
		AceType:  data[0],
		AceFlags: data[1],
		AceSize:  binary.LittleEndian.Uint16(data[2:4]),
	}
	mask := binary.LittleEndian.Uint32(data[4:8])
	sid, sidLen, err := sid.ParseSID(data[8:])
	if err != nil {
		return nil, err
	}
	attr := binary.LittleEndian.Uint32(data[8+sidLen : 8+sidLen+4])
	return &SystemMandatoryLabelACE{Header: header, Mask: mask, SID: sid, Attr: attr}, nil
}
