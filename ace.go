package gontsd

import (
	"encoding/binary"
	"fmt"
)

const (
	ACCESS_ALLOWED_ACE_TYPE                 = 0x00
	ACCESS_DENIED_ACE_TYPE                  = 0x01
	ACCESS_ALLOWED_OBJECT_ACE_TYPE          = 0x05
	ACCESS_DENIED_OBJECT_ACE_TYPE           = 0x06
	ACCESS_ALLOWED_CALLBACK_ACE_TYPE        = 0x09
	ACCESS_DENIED_CALLBACK_ACE_TYPE         = 0x0A
	ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE = 0x0B
	ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE  = 0x0C
)

// ACEHeader is the common header for all ACE types.
// See: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586
type ACEHeader struct {
	AceType  uint8
	AceFlags uint8
	AceSize  uint16
}

// ACE is the interface implemented by all Access Control Entry types.
type ACE interface {
	Type() uint8
	Size() uint16
	String() string
	GetSID() *SID
	GetMask() uint32
	GetFlags() []string
	GetObjectTypeGUID() string          // empty string for non-object ACEs
	GetInheritedObjectTypeGUID() string // empty string for non-object ACEs
}

type baseACE struct {
	Header ACEHeader
	Mask   uint32
	SID    *SID
	Flags  []string
}

func (b *baseACE) Type() uint8                        { return b.Header.AceType }
func (b *baseACE) Size() uint16                       { return b.Header.AceSize }
func (b *baseACE) GetSID() *SID                       { return b.SID }
func (b *baseACE) GetMask() uint32                    { return b.Mask }
func (b *baseACE) GetFlags() []string                 { return b.Flags }
func (b *baseACE) GetObjectTypeGUID() string          { return "" }
func (b *baseACE) GetInheritedObjectTypeGUID() string { return "" }

type baseObjectACE struct {
	Header              ACEHeader
	Mask                uint32
	ObjectFlags         uint32
	ObjectType          [16]byte
	InheritedObjectType [16]byte
	SID                 *SID
	FlagStrings         []string
}

func (b *baseObjectACE) Type() uint8        { return b.Header.AceType }
func (b *baseObjectACE) Size() uint16       { return b.Header.AceSize }
func (b *baseObjectACE) GetSID() *SID       { return b.SID }
func (b *baseObjectACE) GetMask() uint32    { return b.Mask }
func (b *baseObjectACE) GetFlags() []string { return b.FlagStrings }

func (b *baseObjectACE) GetObjectTypeGUID() string {
	if b.ObjectFlags&0x1 == 0 {
		return ""
	}
	guid, err := guidBytesToString(b.ObjectType[:])
	if err != nil {
		return ""
	}
	return guid
}

func (b *baseObjectACE) GetInheritedObjectTypeGUID() string {
	if b.ObjectFlags&0x2 == 0 {
		return ""
	}
	guid, err := guidBytesToString(b.InheritedObjectType[:])
	if err != nil {
		return ""
	}
	return guid
}

// AccessAllowedACE grants access rights to a trustee.
type AccessAllowedACE struct {
	baseACE
}

func (a *AccessAllowedACE) String() string {
	return fmt.Sprintf(`AccessAllowedACE {
  Mask: 0x%08X
  SID:  %s
  Flags: %v
}`, a.Mask, a.SID, a.Flags)
}

// AccessDeniedACE denies access rights to a trustee.
type AccessDeniedACE struct {
	baseACE
}

func (a *AccessDeniedACE) String() string {
	return fmt.Sprintf(`AccessDeniedACE {
  Mask: 0x%08X
  SID:  %s
  Flags: %v
}`, a.Mask, a.SID, a.Flags)
}

// AccessAllowedObjectACE grants access rights to a trustee for a specific object type or property.
type AccessAllowedObjectACE struct {
	baseObjectACE
}

func (a *AccessAllowedObjectACE) String() string {
	return fmt.Sprintf(`AccessAllowedObjectACE {
  Mask: 0x%08X
  SID:  %s
  Flags %s
}`, a.Mask, a.SID, a.FlagStrings)
}

// AccessDeniedObjectACE denies access rights to a trustee for a specific object type or property.
type AccessDeniedObjectACE struct {
	baseObjectACE
}

func (a *AccessDeniedObjectACE) String() string {
	return fmt.Sprintf(`AccessDeniedObjectACE {
  Mask: 0x%08X
  SID:  %s
  Flags %s
}`, a.Mask, a.SID, a.FlagStrings)
}

// Callback ACE types store conditional expressions as raw bytes in ApplicationData.
// See MS-DTYP 2.4.4.17 for the conditional expression format.
type AccessAllowedCallbackACE struct {
	baseACE
	ApplicationData []byte
}

func (a *AccessAllowedCallbackACE) String() string {
	return fmt.Sprintf(`AccessAllowedCallbackACE {
  Mask: 0x%08X
  SID:  %s
  Flags: %v
  Condition: %d bytes
}`, a.Mask, a.SID, a.Flags, len(a.ApplicationData))
}

// AccessDeniedCallbackACE denies access rights with a conditional expression.
type AccessDeniedCallbackACE struct {
	baseACE
	ApplicationData []byte
}

func (a *AccessDeniedCallbackACE) String() string {
	return fmt.Sprintf(`AccessDeniedCallbackACE {
  Mask: 0x%08X
  SID:  %s
  Flags: %v
  Condition: %d bytes
}`, a.Mask, a.SID, a.Flags, len(a.ApplicationData))
}

// AccessAllowedCallbackObjectACE grants access rights to a specific object type with a conditional expression.
type AccessAllowedCallbackObjectACE struct {
	baseObjectACE
	ApplicationData []byte
}

func (a *AccessAllowedCallbackObjectACE) String() string {
	return fmt.Sprintf(`AccessAllowedCallbackObjectACE {
  Mask: 0x%08X
  SID:  %s
  Flags: %v
  Condition: %d bytes
}`, a.Mask, a.SID, a.FlagStrings, len(a.ApplicationData))
}

// AccessDeniedCallbackObjectACE denies access rights to a specific object type with a conditional expression.
type AccessDeniedCallbackObjectACE struct {
	baseObjectACE
	ApplicationData []byte
}

func (a *AccessDeniedCallbackObjectACE) String() string {
	return fmt.Sprintf(`AccessDeniedCallbackObjectACE {
  Mask: 0x%08X
  SID:  %s
  Flags: %v
  Condition: %d bytes
}`, a.Mask, a.SID, a.FlagStrings, len(a.ApplicationData))
}

func parseACE(data []byte) (ACE, int, error) {
	if len(data) < 8 {
		return nil, 0, fmt.Errorf("data too short for ACE header")
	}

	switch data[0] {
	case ACCESS_ALLOWED_ACE_TYPE:
		a, err := parseAccessAllowedACE(data)
		if err != nil {
			return nil, 0, err
		}
		return a, int(a.Size()), nil
	case ACCESS_DENIED_ACE_TYPE:
		a, err := parseAccessDeniedACE(data)
		if err != nil {
			return nil, 0, err
		}
		return a, int(a.Size()), nil
	case ACCESS_ALLOWED_OBJECT_ACE_TYPE:
		a, err := parseAccessAllowedObjectACE(data)
		if err != nil {
			return nil, 0, err
		}
		return a, int(a.Size()), nil
	case ACCESS_DENIED_OBJECT_ACE_TYPE:
		a, err := parseAccessDeniedObjectACE(data)
		if err != nil {
			return nil, 0, err
		}
		return a, int(a.Size()), nil
	case ACCESS_ALLOWED_CALLBACK_ACE_TYPE:
		a, err := parseAccessAllowedCallbackACE(data)
		if err != nil {
			return nil, 0, err
		}
		return a, int(a.Size()), nil
	case ACCESS_DENIED_CALLBACK_ACE_TYPE:
		a, err := parseAccessDeniedCallbackACE(data)
		if err != nil {
			return nil, 0, err
		}
		return a, int(a.Size()), nil
	case ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE:
		a, err := parseAccessAllowedCallbackObjectACE(data)
		if err != nil {
			return nil, 0, err
		}
		return a, int(a.Size()), nil
	case ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE:
		a, err := parseAccessDeniedCallbackObjectACE(data)
		if err != nil {
			return nil, 0, err
		}
		return a, int(a.Size()), nil
	default:
		return nil, 0, fmt.Errorf("unsupported ACE type: 0x%02X", data[0])
	}
}

func parseACEHeader(data []byte) (ACEHeader, error) {
	if len(data) < 4 {
		return ACEHeader{}, fmt.Errorf("data too short for ACE header")
	}
	return ACEHeader{
		AceType:  data[0],
		AceFlags: data[1],
		AceSize:  binary.LittleEndian.Uint16(data[2:4]),
	}, nil
}

func parseBaseACE(data []byte) (baseACE, error) {
	header, err := parseACEHeader(data)
	if err != nil {
		return baseACE{}, err
	}
	if len(data) < 8 {
		return baseACE{}, fmt.Errorf("data too short for ACE mask")
	}
	mask := binary.LittleEndian.Uint32(data[4:8])
	sid, _, err := parseSID(data[8:])
	if err != nil {
		return baseACE{}, err
	}
	return baseACE{
		Header: header,
		Mask:   mask,
		SID:    sid,
		Flags:  CheckFlags(mask),
	}, nil
}

func parseBaseACEWithSIDLen(data []byte) (baseACE, int, error) {
	header, err := parseACEHeader(data)
	if err != nil {
		return baseACE{}, 0, err
	}
	if len(data) < 8 {
		return baseACE{}, 0, fmt.Errorf("data too short for ACE mask")
	}
	mask := binary.LittleEndian.Uint32(data[4:8])
	sid, sidLen, err := parseSID(data[8:])
	if err != nil {
		return baseACE{}, 0, err
	}
	return baseACE{
		Header: header,
		Mask:   mask,
		SID:    sid,
		Flags:  CheckFlags(mask),
	}, sidLen, nil
}

func parseBaseObjectACE(data []byte) (baseObjectACE, int, error) {
	header, err := parseACEHeader(data)
	if err != nil {
		return baseObjectACE{}, 0, err
	}
	if len(data) < int(header.AceSize) {
		return baseObjectACE{}, 0, fmt.Errorf("ACE claims size %d, but only %d bytes available", header.AceSize, len(data))
	}

	mask := binary.LittleEndian.Uint32(data[4:8])
	flags := binary.LittleEndian.Uint32(data[8:12])

	offset := 12
	var objType, inhType [16]byte

	if flags&0x1 != 0 {
		if offset+16 > len(data) {
			return baseObjectACE{}, 0, fmt.Errorf("not enough data for ObjectType")
		}
		copy(objType[:], data[offset:offset+16])
		offset += 16
	}
	if flags&0x2 != 0 {
		if offset+16 > len(data) {
			return baseObjectACE{}, 0, fmt.Errorf("not enough data for InheritedObjectType")
		}
		copy(inhType[:], data[offset:offset+16])
		offset += 16
	}

	if offset >= len(data) {
		return baseObjectACE{}, 0, fmt.Errorf("not enough data to read SID (offset %d, len %d)", offset, len(data))
	}

	sid, sidLen, err := parseSID(data[offset:])
	if err != nil {
		return baseObjectACE{}, 0, err
	}

	return baseObjectACE{
		Header:              header,
		Mask:                mask,
		ObjectFlags:         flags,
		ObjectType:          objType,
		InheritedObjectType: inhType,
		SID:                 sid,
		FlagStrings:         CheckFlags(mask),
	}, offset + sidLen, nil
}

func parseAccessAllowedACE(data []byte) (*AccessAllowedACE, error) {
	base, err := parseBaseACE(data)
	if err != nil {
		return nil, err
	}
	return &AccessAllowedACE{baseACE: base}, nil
}

func parseAccessDeniedACE(data []byte) (*AccessDeniedACE, error) {
	base, err := parseBaseACE(data)
	if err != nil {
		return nil, err
	}
	return &AccessDeniedACE{baseACE: base}, nil
}

func parseAccessAllowedObjectACE(data []byte) (*AccessAllowedObjectACE, error) {
	base, _, err := parseBaseObjectACE(data)
	if err != nil {
		return nil, err
	}
	return &AccessAllowedObjectACE{baseObjectACE: base}, nil
}

func parseAccessDeniedObjectACE(data []byte) (*AccessDeniedObjectACE, error) {
	base, _, err := parseBaseObjectACE(data)
	if err != nil {
		return nil, err
	}
	return &AccessDeniedObjectACE{baseObjectACE: base}, nil
}

func parseAccessAllowedCallbackACE(data []byte) (*AccessAllowedCallbackACE, error) {
	base, sidLen, err := parseBaseACEWithSIDLen(data)
	if err != nil {
		return nil, err
	}
	if len(data) < int(base.Header.AceSize) {
		return nil, fmt.Errorf("ACE claims size %d, but only %d bytes available", base.Header.AceSize, len(data))
	}

	// ApplicationData follows the SID
	appDataStart := 8 + sidLen
	var appData []byte
	if appDataStart < int(base.Header.AceSize) {
		appData = make([]byte, int(base.Header.AceSize)-appDataStart)
		copy(appData, data[appDataStart:base.Header.AceSize])
	}

	return &AccessAllowedCallbackACE{
		baseACE:         base,
		ApplicationData: appData,
	}, nil
}

func parseAccessDeniedCallbackACE(data []byte) (*AccessDeniedCallbackACE, error) {
	base, sidLen, err := parseBaseACEWithSIDLen(data)
	if err != nil {
		return nil, err
	}
	if len(data) < int(base.Header.AceSize) {
		return nil, fmt.Errorf("ACE claims size %d, but only %d bytes available", base.Header.AceSize, len(data))
	}

	// ApplicationData follows the SID
	appDataStart := 8 + sidLen
	var appData []byte
	if appDataStart < int(base.Header.AceSize) {
		appData = make([]byte, int(base.Header.AceSize)-appDataStart)
		copy(appData, data[appDataStart:base.Header.AceSize])
	}

	return &AccessDeniedCallbackACE{
		baseACE:         base,
		ApplicationData: appData,
	}, nil
}

func parseAccessAllowedCallbackObjectACE(data []byte) (*AccessAllowedCallbackObjectACE, error) {
	base, sidEndOffset, err := parseBaseObjectACE(data)
	if err != nil {
		return nil, err
	}

	// ApplicationData follows the SID
	var appData []byte
	if sidEndOffset < int(base.Header.AceSize) {
		appData = make([]byte, int(base.Header.AceSize)-sidEndOffset)
		copy(appData, data[sidEndOffset:base.Header.AceSize])
	}

	return &AccessAllowedCallbackObjectACE{
		baseObjectACE:   base,
		ApplicationData: appData,
	}, nil
}

func parseAccessDeniedCallbackObjectACE(data []byte) (*AccessDeniedCallbackObjectACE, error) {
	base, sidEndOffset, err := parseBaseObjectACE(data)
	if err != nil {
		return nil, err
	}

	// ApplicationData follows the SID
	var appData []byte
	if sidEndOffset < int(base.Header.AceSize) {
		appData = make([]byte, int(base.Header.AceSize)-sidEndOffset)
		copy(appData, data[sidEndOffset:base.Header.AceSize])
	}

	return &AccessDeniedCallbackObjectACE{
		baseObjectACE:   base,
		ApplicationData: appData,
	}, nil
}
