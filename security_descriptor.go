package gontsd

import (
	"encoding/binary"
	"fmt"
)

type SecurityDescriptor struct {
	Revision     uint8
	Sbz1         uint8
	ControlFlags uint16
	OwnerSID     *SID
	GroupSID     *SID
	DACL         *ACL
	SACL         *ACL

	OwnerOffset uint32
	GroupOffset uint32
	SaclOffset  uint32
	DaclOffset  uint32
}

func Parse(data []byte) (*SecurityDescriptor, error) {
	return parseSecurityDescriptor(data)
}

func ParseToString(data []byte) (string, error) {
	sd, err := parseSecurityDescriptor(data)
	if err != nil {
		return "", err
	}
	return sd.String(), nil
}

func parseSecurityDescriptor(descriptor []byte) (*SecurityDescriptor, error) {
	if len(descriptor) < 20 {
		return nil, fmt.Errorf("descriptor too short")
	}

	sd := &SecurityDescriptor{
		Revision:     descriptor[0],
		Sbz1:         descriptor[1],
		ControlFlags: binary.LittleEndian.Uint16(descriptor[2:4]),
		OwnerOffset:  binary.LittleEndian.Uint32(descriptor[4:8]),
		GroupOffset:  binary.LittleEndian.Uint32(descriptor[8:12]),
		SaclOffset:   binary.LittleEndian.Uint32(descriptor[12:16]),
		DaclOffset:   binary.LittleEndian.Uint32(descriptor[16:20]),
	}

	if sd.DaclOffset > 0 && int(sd.DaclOffset) < len(descriptor) {
		dacl := &ACL{
			Revision: descriptor[sd.DaclOffset],
			Sbz1:     descriptor[sd.DaclOffset+1],
			Size:     binary.LittleEndian.Uint16(descriptor[sd.DaclOffset+2:]),
			Count:    binary.LittleEndian.Uint16(descriptor[sd.DaclOffset+4:]),
			Sbz2:     binary.LittleEndian.Uint16(descriptor[sd.DaclOffset+6:]),
		}
		offset := sd.DaclOffset + 8
		dacl.ACEs = make([]ACE, dacl.Count)
		for i := 0; i < int(dacl.Count); i++ {
			ace, aceLen, err := parseACE(descriptor[offset:])
			if err != nil {
				return nil, err
			}
			dacl.ACEs[i] = ace
			offset += uint32(aceLen)
		}
		sd.DACL = dacl
	}

	if sd.OwnerOffset > 0 {
		ownerSID, _, _ := parseSID(descriptor[sd.OwnerOffset:])
		sd.OwnerSID = ownerSID
	}
	if sd.GroupOffset > 0 {
		groupSID, _, _ := parseSID(descriptor[sd.GroupOffset:])
		sd.GroupSID = groupSID
	}

	return sd, nil
}

func (sd *SecurityDescriptor) String() string {
	if sd == nil {
		return "<nil>"
	}
	return fmt.Sprintf(`Security Descriptor:
  Revision:      %d
  ControlFlags:  0x%04X
  OwnerSID:      %s
  GroupSID:      %s

  DACL:
%s
  SACL:
%s`,
		sd.Revision,
		sd.ControlFlags,
		sd.OwnerSID,
		sd.GroupSID,
		indent(sd.DACL.String(), "    "),
		indent(sd.SACL.String(), "    "),
	)
}
