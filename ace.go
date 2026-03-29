package gontsd

import (
	"encoding/binary"
	"fmt"
)

// ACEType represents the type byte of an Access Control Entry.
// See: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586
type ACEType uint8

const (
	AccessAllowedACEType         ACEType = 0x00
	AccessDeniedACEType          ACEType = 0x01
	SystemAuditACEType           ACEType = 0x02
	AccessAllowedObjectACEType   ACEType = 0x05
	AccessDeniedObjectACEType    ACEType = 0x06
	SystemAuditObjectACEType     ACEType = 0x07
	AccessAllowedCallbackACEType ACEType = 0x09
	AccessDeniedCallbackACEType  ACEType = 0x0A
	AccessAllowedCallbackObjectACEType ACEType = 0x0B
	AccessDeniedCallbackObjectACEType ACEType = 0x0C
)

func (t ACEType) String() string {
	switch t {
	case AccessAllowedACEType:
		return "AccessAllowed"
	case AccessDeniedACEType:
		return "AccessDenied"
	case SystemAuditACEType:
		return "SystemAudit"
	case AccessAllowedObjectACEType:
		return "AccessAllowedObject"
	case AccessDeniedObjectACEType:
		return "AccessDeniedObject"
	case SystemAuditObjectACEType:
		return "SystemAuditObject"
	case AccessAllowedCallbackACEType:
		return "AccessAllowedCallback"
	case AccessDeniedCallbackACEType:
		return "AccessDeniedCallback"
	case AccessAllowedCallbackObjectACEType:
		return "AccessAllowedCallbackObject"
	case AccessDeniedCallbackObjectACEType:
		return "AccessDeniedCallbackObject"
	default:
		return fmt.Sprintf("Unknown(0x%02X)", uint8(t))
	}
}

// ACEHeader is the common header for all ACE types.
// See: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586
type ACEHeader struct {
	AceType  ACEType
	AceFlags uint8
	AceSize  uint16
}

// ACE is the interface implemented by all Access Control Entry types.
type ACE interface {
	Type() ACEType
	Size() uint16
	String() string
	SID() *SID
	Mask() AccessMask
	AceFlags() ACEFlags
	ApplicationData() []byte
	ObjectTypeGUID() string
	InheritedObjectTypeGUID() string
}

// aceBase contains the fields common to every ACE type.
type aceBase struct {
	Header   ACEHeader
	mask     uint32
	sid      *SID
}

func (b *aceBase) Type() ACEType                   { return b.Header.AceType }
func (b *aceBase) Size() uint16                    { return b.Header.AceSize }
func (b *aceBase) SID() *SID                       { return b.sid }
func (b *aceBase) Mask() AccessMask                { return AccessMask(b.mask) }
func (b *aceBase) AceFlags() ACEFlags              { return ACEFlags(b.Header.AceFlags) }
func (b *aceBase) ApplicationData() []byte         { return nil }
func (b *aceBase) ObjectTypeGUID() string          { return "" }
func (b *aceBase) InheritedObjectTypeGUID() string { return "" }

// AccessAllowedACE grants access rights to a trustee.
type AccessAllowedACE struct {
	aceBase
}

func (a *AccessAllowedACE) String() string {
	return fmt.Sprintf("AccessAllowedACE { Mask: 0x%08X, SID: %s, AccessRights: %v }", a.mask, a.sid, a.Mask().Names())
}

// AccessDeniedACE denies access rights to a trustee.
type AccessDeniedACE struct {
	aceBase
}

func (a *AccessDeniedACE) String() string {
	return fmt.Sprintf("AccessDeniedACE { Mask: 0x%08X, SID: %s, AccessRights: %v }", a.mask, a.sid, a.Mask().Names())
}

// SystemAuditACE generates an audit record when a trustee attempts to exercise the specified access rights.
type SystemAuditACE struct {
	aceBase
}

func (a *SystemAuditACE) String() string {
	return fmt.Sprintf("SystemAuditACE { Mask: 0x%08X, SID: %s, AccessRights: %v }", a.mask, a.sid, a.Mask().Names())
}

// SystemAuditObjectACE generates an audit record for a specific object type or property.
type SystemAuditObjectACE struct {
	aceBase
	ObjectFlags         uint32
	ObjectType          [16]byte
	InheritedObjectType [16]byte
}

func (a *SystemAuditObjectACE) ObjectTypeGUID() string {
	return objectTypeGUID(a.ObjectFlags, a.ObjectType)
}

func (a *SystemAuditObjectACE) InheritedObjectTypeGUID() string {
	return inheritedObjectTypeGUID(a.ObjectFlags, a.InheritedObjectType)
}

func (a *SystemAuditObjectACE) String() string {
	return fmt.Sprintf("SystemAuditObjectACE { Mask: 0x%08X, SID: %s, AccessRights: %v }", a.mask, a.sid, a.Mask().Names())
}

// AccessAllowedObjectACE grants access rights to a trustee for a specific object type or property.
type AccessAllowedObjectACE struct {
	aceBase
	ObjectFlags         uint32
	ObjectType          [16]byte
	InheritedObjectType [16]byte
}

func (a *AccessAllowedObjectACE) ObjectTypeGUID() string {
	return objectTypeGUID(a.ObjectFlags, a.ObjectType)
}

func (a *AccessAllowedObjectACE) InheritedObjectTypeGUID() string {
	return inheritedObjectTypeGUID(a.ObjectFlags, a.InheritedObjectType)
}

func (a *AccessAllowedObjectACE) String() string {
	return fmt.Sprintf("AccessAllowedObjectACE { Mask: 0x%08X, SID: %s, AccessRights: %v }", a.mask, a.sid, a.Mask().Names())
}

// AccessDeniedObjectACE denies access rights to a trustee for a specific object type or property.
type AccessDeniedObjectACE struct {
	aceBase
	ObjectFlags         uint32
	ObjectType          [16]byte
	InheritedObjectType [16]byte
}

func (a *AccessDeniedObjectACE) ObjectTypeGUID() string {
	return objectTypeGUID(a.ObjectFlags, a.ObjectType)
}

func (a *AccessDeniedObjectACE) InheritedObjectTypeGUID() string {
	return inheritedObjectTypeGUID(a.ObjectFlags, a.InheritedObjectType)
}

func (a *AccessDeniedObjectACE) String() string {
	return fmt.Sprintf("AccessDeniedObjectACE { Mask: 0x%08X, SID: %s, AccessRights: %v }", a.mask, a.sid, a.Mask().Names())
}

// AccessAllowedCallbackACE grants access rights with a conditional expression.
// See MS-DTYP 2.4.4.17 for the conditional expression format.
//
// TODO: remove ApplicationData() from ACE interface; access via type assertion instead.
type AccessAllowedCallbackACE struct {
	aceBase
	appData []byte
}

func (a *AccessAllowedCallbackACE) ApplicationData() []byte { return a.appData }
func (a *AccessAllowedCallbackACE) String() string {
	return fmt.Sprintf("AccessAllowedCallbackACE { Mask: 0x%08X, SID: %s, Condition: %d bytes }", a.mask, a.sid, len(a.appData))
}

// AccessDeniedCallbackACE denies access rights with a conditional expression.
type AccessDeniedCallbackACE struct {
	aceBase
	appData []byte
}

func (a *AccessDeniedCallbackACE) ApplicationData() []byte { return a.appData }
func (a *AccessDeniedCallbackACE) String() string {
	return fmt.Sprintf("AccessDeniedCallbackACE { Mask: 0x%08X, SID: %s, Condition: %d bytes }", a.mask, a.sid, len(a.appData))
}

// AccessAllowedCallbackObjectACE grants access rights to a specific object type with a conditional expression.
type AccessAllowedCallbackObjectACE struct {
	aceBase
	ObjectFlags         uint32
	ObjectType          [16]byte
	InheritedObjectType [16]byte
	appData             []byte
}

func (a *AccessAllowedCallbackObjectACE) ApplicationData() []byte { return a.appData }
func (a *AccessAllowedCallbackObjectACE) ObjectTypeGUID() string {
	return objectTypeGUID(a.ObjectFlags, a.ObjectType)
}

func (a *AccessAllowedCallbackObjectACE) InheritedObjectTypeGUID() string {
	return inheritedObjectTypeGUID(a.ObjectFlags, a.InheritedObjectType)
}

func (a *AccessAllowedCallbackObjectACE) String() string {
	return fmt.Sprintf("AccessAllowedCallbackObjectACE { Mask: 0x%08X, SID: %s, Condition: %d bytes }", a.mask, a.sid, len(a.appData))
}

// AccessDeniedCallbackObjectACE denies access rights to a specific object type with a conditional expression.
type AccessDeniedCallbackObjectACE struct {
	aceBase
	ObjectFlags         uint32
	ObjectType          [16]byte
	InheritedObjectType [16]byte
	appData             []byte
}

func (a *AccessDeniedCallbackObjectACE) ApplicationData() []byte { return a.appData }
func (a *AccessDeniedCallbackObjectACE) ObjectTypeGUID() string {
	return objectTypeGUID(a.ObjectFlags, a.ObjectType)
}

func (a *AccessDeniedCallbackObjectACE) InheritedObjectTypeGUID() string {
	return inheritedObjectTypeGUID(a.ObjectFlags, a.InheritedObjectType)
}

func (a *AccessDeniedCallbackObjectACE) String() string {
	return fmt.Sprintf("AccessDeniedCallbackObjectACE { Mask: 0x%08X, SID: %s, Condition: %d bytes }", a.mask, a.sid, len(a.appData))
}

// RawACE represents an ACE type that is not explicitly supported.
// The raw bytes are preserved so the ACE can still be compared and displayed.
type RawACE struct {
	aceBase
	RawData []byte
}

func (a *RawACE) String() string {
	return fmt.Sprintf("RawACE { Type: 0x%02X, Size: %d }", uint8(a.Header.AceType), a.Header.AceSize)
}

// GUID helpers for object ACE types.

func objectTypeGUID(flags uint32, objType [16]byte) string {
	if flags&0x1 == 0 {
		return ""
	}
	guid, err := GUIDBytesToString(objType[:])
	if err != nil {
		return ""
	}
	return guid
}

func inheritedObjectTypeGUID(flags uint32, inhType [16]byte) string {
	if flags&0x2 == 0 {
		return ""
	}
	guid, err := GUIDBytesToString(inhType[:])
	if err != nil {
		return ""
	}
	return guid
}

// Parsing functions.

func parseACE(data []byte) (ACE, int, error) {
	if len(data) < 8 {
		return nil, 0, fmt.Errorf("data too short for ACE header")
	}

	switch ACEType(data[0]) {
	case AccessAllowedACEType:
		a, err := parseSimpleACE(data)
		if err != nil {
			return nil, 0, err
		}
		return &AccessAllowedACE{aceBase: a}, int(a.Header.AceSize), nil
	case AccessDeniedACEType:
		a, err := parseSimpleACE(data)
		if err != nil {
			return nil, 0, err
		}
		return &AccessDeniedACE{aceBase: a}, int(a.Header.AceSize), nil
	case SystemAuditACEType:
		a, err := parseSimpleACE(data)
		if err != nil {
			return nil, 0, err
		}
		return &SystemAuditACE{aceBase: a}, int(a.Header.AceSize), nil
	case AccessAllowedObjectACEType:
		return parseObjectACE(data, func(base aceBase, flags uint32, obj, inh [16]byte) ACE {
			return &AccessAllowedObjectACE{aceBase: base, ObjectFlags: flags, ObjectType: obj, InheritedObjectType: inh}
		})
	case AccessDeniedObjectACEType:
		return parseObjectACE(data, func(base aceBase, flags uint32, obj, inh [16]byte) ACE {
			return &AccessDeniedObjectACE{aceBase: base, ObjectFlags: flags, ObjectType: obj, InheritedObjectType: inh}
		})
	case SystemAuditObjectACEType:
		return parseObjectACE(data, func(base aceBase, flags uint32, obj, inh [16]byte) ACE {
			return &SystemAuditObjectACE{aceBase: base, ObjectFlags: flags, ObjectType: obj, InheritedObjectType: inh}
		})
	case AccessAllowedCallbackACEType:
		return parseCallbackACE(data, func(base aceBase, appData []byte) ACE {
			return &AccessAllowedCallbackACE{aceBase: base, appData: appData}
		})
	case AccessDeniedCallbackACEType:
		return parseCallbackACE(data, func(base aceBase, appData []byte) ACE {
			return &AccessDeniedCallbackACE{aceBase: base, appData: appData}
		})
	case AccessAllowedCallbackObjectACEType:
		return parseCallbackObjectACE(data, func(base aceBase, flags uint32, obj, inh [16]byte, appData []byte) ACE {
			return &AccessAllowedCallbackObjectACE{aceBase: base, ObjectFlags: flags, ObjectType: obj, InheritedObjectType: inh, appData: appData}
		})
	case AccessDeniedCallbackObjectACEType:
		return parseCallbackObjectACE(data, func(base aceBase, flags uint32, obj, inh [16]byte, appData []byte) ACE {
			return &AccessDeniedCallbackObjectACE{aceBase: base, ObjectFlags: flags, ObjectType: obj, InheritedObjectType: inh, appData: appData}
		})
	default:
		header, err := parseACEHeader(data)
		if err != nil {
			return nil, 0, err
		}
		if int(header.AceSize) > len(data) {
			return nil, 0, fmt.Errorf("ACE type 0x%02X claims size %d, but only %d bytes available", header.AceType, header.AceSize, len(data))
		}
		raw := make([]byte, header.AceSize)
		copy(raw, data[:header.AceSize])

		// Try to parse common fields (mask + SID) since most unsupported
		// ACE types share the standard layout.
		base, _, parseErr := parseAceBase(data)
		if parseErr != nil {
			base = aceBase{Header: header}
		}
		return &RawACE{aceBase: base, RawData: raw}, int(header.AceSize), nil
	}
}

func parseACEHeader(data []byte) (ACEHeader, error) {
	if len(data) < 4 {
		return ACEHeader{}, fmt.Errorf("data too short for ACE header")
	}
	return ACEHeader{
		AceType:  ACEType(data[0]),
		AceFlags: data[1],
		AceSize:  binary.LittleEndian.Uint16(data[2:4]),
	}, nil
}

// parseAceBase parses the common header + mask + SID, returning the base and
// the number of bytes consumed for the SID (needed by callback ACE types).
func parseAceBase(data []byte) (aceBase, int, error) {
	header, err := parseACEHeader(data)
	if err != nil {
		return aceBase{}, 0, err
	}
	if len(data) < 8 {
		return aceBase{}, 0, fmt.Errorf("data too short for ACE mask")
	}
	mask := binary.LittleEndian.Uint32(data[4:8])
	sid, sidLen, err := parseSID(data[8:])
	if err != nil {
		return aceBase{}, 0, err
	}
	return aceBase{
		Header: header,
		mask:   mask,
		sid:    sid,
	}, sidLen, nil
}

func parseSimpleACE(data []byte) (aceBase, error) {
	base, _, err := parseAceBase(data)
	return base, err
}

func parseObjectACE(data []byte, build func(aceBase, uint32, [16]byte, [16]byte) ACE) (ACE, int, error) {
	header, err := parseACEHeader(data)
	if err != nil {
		return nil, 0, err
	}
	if len(data) < int(header.AceSize) {
		return nil, 0, fmt.Errorf("ACE claims size %d, but only %d bytes available", header.AceSize, len(data))
	}

	mask := binary.LittleEndian.Uint32(data[4:8])
	objFlags := binary.LittleEndian.Uint32(data[8:12])

	offset := 12
	var objType, inhType [16]byte

	if objFlags&0x1 != 0 {
		if offset+16 > len(data) {
			return nil, 0, fmt.Errorf("not enough data for ObjectType")
		}
		copy(objType[:], data[offset:offset+16])
		offset += 16
	}
	if objFlags&0x2 != 0 {
		if offset+16 > len(data) {
			return nil, 0, fmt.Errorf("not enough data for InheritedObjectType")
		}
		copy(inhType[:], data[offset:offset+16])
		offset += 16
	}

	if offset >= len(data) {
		return nil, 0, fmt.Errorf("not enough data to read SID (offset %d, len %d)", offset, len(data))
	}

	sid, _, err := parseSID(data[offset:])
	if err != nil {
		return nil, 0, err
	}

	base := aceBase{
		Header: header,
		mask:   mask,
		sid:    sid,
	}

	return build(base, objFlags, objType, inhType), int(header.AceSize), nil
}

func parseCallbackACE(data []byte, build func(aceBase, []byte) ACE) (ACE, int, error) {
	base, sidLen, err := parseAceBase(data)
	if err != nil {
		return nil, 0, err
	}
	if len(data) < int(base.Header.AceSize) {
		return nil, 0, fmt.Errorf("ACE claims size %d, but only %d bytes available", base.Header.AceSize, len(data))
	}

	appDataStart := 8 + sidLen
	var appData []byte
	if appDataStart < int(base.Header.AceSize) {
		appData = make([]byte, int(base.Header.AceSize)-appDataStart)
		copy(appData, data[appDataStart:base.Header.AceSize])
	}

	return build(base, appData), int(base.Header.AceSize), nil
}

func parseCallbackObjectACE(data []byte, build func(aceBase, uint32, [16]byte, [16]byte, []byte) ACE) (ACE, int, error) {
	header, err := parseACEHeader(data)
	if err != nil {
		return nil, 0, err
	}
	if len(data) < int(header.AceSize) {
		return nil, 0, fmt.Errorf("ACE claims size %d, but only %d bytes available", header.AceSize, len(data))
	}

	mask := binary.LittleEndian.Uint32(data[4:8])
	objFlags := binary.LittleEndian.Uint32(data[8:12])

	offset := 12
	var objType, inhType [16]byte

	if objFlags&0x1 != 0 {
		if offset+16 > len(data) {
			return nil, 0, fmt.Errorf("not enough data for ObjectType")
		}
		copy(objType[:], data[offset:offset+16])
		offset += 16
	}
	if objFlags&0x2 != 0 {
		if offset+16 > len(data) {
			return nil, 0, fmt.Errorf("not enough data for InheritedObjectType")
		}
		copy(inhType[:], data[offset:offset+16])
		offset += 16
	}

	if offset >= len(data) {
		return nil, 0, fmt.Errorf("not enough data to read SID (offset %d, len %d)", offset, len(data))
	}

	sid, sidLen, err := parseSID(data[offset:])
	if err != nil {
		return nil, 0, err
	}

	base := aceBase{
		Header: header,
		mask:   mask,
		sid:    sid,
	}

	appDataStart := offset + sidLen
	var appData []byte
	if appDataStart < int(header.AceSize) {
		appData = make([]byte, int(header.AceSize)-appDataStart)
		copy(appData, data[appDataStart:header.AceSize])
	}

	return build(base, objFlags, objType, inhType, appData), int(header.AceSize), nil
}
