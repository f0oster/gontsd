package ace

// ACE type constants
const (
	ACCESS_ALLOWED_ACE_TYPE         = 0x00
	ACCESS_DENIED_ACE_TYPE          = 0x01
	SYSTEM_AUDIT_ACE_TYPE           = 0x02
	ACCESS_ALLOWED_OBJECT_ACE_TYPE  = 0x05
	SYSTEM_MANDATORY_LABEL_ACE_TYPE = 0x11 // not yet implemented (SACL only)
)

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586
type ACEHeader struct {
	AceType  uint8
	AceFlags uint8
	AceSize  uint16
}

// GenericACE is implemented by all ACE type structs
type GenericACE interface {
	Type() uint8
	Size() uint16
	String() string
}
