package gontsd

import (
	"encoding/binary"
	"fmt"
)

// SecurityDescriptor represents a Windows NT security descriptor (SECURITY_DESCRIPTOR).
type SecurityDescriptor struct {
	Revision     uint8
	sbz1         uint8
	ControlFlags uint16
	OwnerSID     *SID
	GroupSID     *SID
	DACL         *ACL
	SACL         *ACL

	ownerOffset uint32
	groupOffset uint32
	saclOffset  uint32
	daclOffset  uint32
}

// Parse parses binary ntSecurityDescriptor data into a SecurityDescriptor.
func Parse(data []byte) (*SecurityDescriptor, error) {
	return parseSecurityDescriptor(data)
}

// ParseToString parses binary ntSecurityDescriptor data and returns a string representation.
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
		sbz1:         descriptor[1],
		ControlFlags: binary.LittleEndian.Uint16(descriptor[2:4]),
		ownerOffset:  binary.LittleEndian.Uint32(descriptor[4:8]),
		groupOffset:  binary.LittleEndian.Uint32(descriptor[8:12]),
		saclOffset:   binary.LittleEndian.Uint32(descriptor[12:16]),
		daclOffset:   binary.LittleEndian.Uint32(descriptor[16:20]),
	}

	if sd.daclOffset > 0 && int(sd.daclOffset) < len(descriptor) {
		dacl := &ACL{
			Revision: descriptor[sd.daclOffset],
			sbz1:     descriptor[sd.daclOffset+1],
			Size:     binary.LittleEndian.Uint16(descriptor[sd.daclOffset+2:]),
			Count:    binary.LittleEndian.Uint16(descriptor[sd.daclOffset+4:]),
			sbz2:     binary.LittleEndian.Uint16(descriptor[sd.daclOffset+6:]),
		}
		offset := sd.daclOffset + 8
		dacl.ACEs = make([]ACE, dacl.Count)
		for i := 0; i < int(dacl.Count); i++ {
			ace, aceLen, err := parseACE(descriptor[offset:])
			if err != nil {
				return nil, fmt.Errorf("failed to parse DACL ACE %d: %w", i, err)
			}
			dacl.ACEs[i] = ace
			offset += uint32(aceLen)
		}
		sd.DACL = dacl
	}

	if sd.saclOffset > 0 && int(sd.saclOffset) < len(descriptor) {
		sacl := &ACL{
			Revision: descriptor[sd.saclOffset],
			sbz1:     descriptor[sd.saclOffset+1],
			Size:     binary.LittleEndian.Uint16(descriptor[sd.saclOffset+2:]),
			Count:    binary.LittleEndian.Uint16(descriptor[sd.saclOffset+4:]),
			sbz2:     binary.LittleEndian.Uint16(descriptor[sd.saclOffset+6:]),
		}
		offset := sd.saclOffset + 8
		sacl.ACEs = make([]ACE, sacl.Count)
		for i := 0; i < int(sacl.Count); i++ {
			ace, aceLen, err := parseACE(descriptor[offset:])
			if err != nil {
				return nil, fmt.Errorf("failed to parse SACL ACE %d: %w", i, err)
			}
			sacl.ACEs[i] = ace
			offset += uint32(aceLen)
		}
		sd.SACL = sacl
	}

	if sd.ownerOffset > 0 && int(sd.ownerOffset) < len(descriptor) {
		ownerSID, _, err := parseSID(descriptor[sd.ownerOffset:])
		if err != nil {
			return nil, fmt.Errorf("failed to parse owner SID: %w", err)
		}
		sd.OwnerSID = ownerSID
	}
	if sd.groupOffset > 0 && int(sd.groupOffset) < len(descriptor) {
		groupSID, _, err := parseSID(descriptor[sd.groupOffset:])
		if err != nil {
			return nil, fmt.Errorf("failed to parse group SID: %w", err)
		}
		sd.GroupSID = groupSID
	}

	return sd, nil
}

// CollectSIDs returns all unique SIDs referenced by this security descriptor,
// including owner, group, and all ACE SIDs from the DACL and SACL.
func (sd *SecurityDescriptor) CollectSIDs() []*SID {
	if sd == nil {
		return nil
	}

	seen := make(map[string]bool)
	var sids []*SID

	add := func(sid *SID) {
		if sid != nil && !seen[sid.Parsed] {
			seen[sid.Parsed] = true
			sids = append(sids, sid)
		}
	}

	add(sd.OwnerSID)
	add(sd.GroupSID)

	for _, acl := range []*ACL{sd.DACL, sd.SACL} {
		if acl == nil {
			continue
		}
		for _, ace := range acl.ACEs {
			add(ace.GetSID())
		}
	}

	return sids
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
