package gontsd

import "strings"

// AccessMask represents the 32-bit access rights bitmask in an ACE.
type AccessMask uint32

const (
	RIGHT_DS_CREATE_CHILD            AccessMask = 0x00000001 // CC: Create child objects.
	RIGHT_DS_DELETE_CHILD            AccessMask = 0x00000002 // DC: Delete child objects.
	RIGHT_DS_LIST_CONTENTS           AccessMask = 0x00000004 // LC: List child objects.
	RIGHT_DS_WRITE_PROPERTY_EXTENDED AccessMask = 0x00000008 // VW: Validated write operation.
	RIGHT_DS_READ_PROPERTY           AccessMask = 0x00000010 // RP: Read properties of the object.
	RIGHT_DS_WRITE_PROPERTY          AccessMask = 0x00000020 // WP: Write properties of the object.
	RIGHT_DS_DELETE_TREE             AccessMask = 0x00000040 // DT: Delete-Tree operation.
	RIGHT_DS_LIST_OBJECT             AccessMask = 0x00000080 // LO: List a particular object.
	RIGHT_DS_CONTROL_ACCESS          AccessMask = 0x00000100 // CR: Perform operations controlled by a control access right.
	RIGHT_DELETE                     AccessMask = 0x00010000 // DE: Delete the object.
	RIGHT_READ_CONTROL               AccessMask = 0x00020000 // RC: Read data from the security descriptor.
	RIGHT_WRITE_DAC                  AccessMask = 0x00040000 // WD: Modify the DACL in the security descriptor.
	RIGHT_WRITE_OWNER                AccessMask = 0x00080000 // WO: Modify the owner of an object.
	RIGHT_GENERIC_ALL                AccessMask = 0x10000000 // GA: Full access rights.
	RIGHT_GENERIC_EXECUTE            AccessMask = 0x20000000 // GX: Read permissions and list container contents.
	RIGHT_GENERIC_WRITE              AccessMask = 0x40000000 // GW: Write properties and perform validated writes.
	RIGHT_GENERIC_READ               AccessMask = 0x80000000 // GR: Read permissions and properties, and list object names.
)

// Has reports whether flag is set in the mask.
func (m AccessMask) Has(flag AccessMask) bool {
	return m&flag != 0
}

type accessFlagEntry struct {
	mask AccessMask
	name string
}

var accessFlags = []accessFlagEntry{
	{RIGHT_DS_CREATE_CHILD, "RIGHT_DS_CREATE_CHILD"},
	{RIGHT_DS_DELETE_CHILD, "RIGHT_DS_DELETE_CHILD"},
	{RIGHT_DS_LIST_CONTENTS, "RIGHT_DS_LIST_CONTENTS"},
	{RIGHT_DS_WRITE_PROPERTY_EXTENDED, "RIGHT_DS_WRITE_PROPERTY_EXTENDED"},
	{RIGHT_DS_READ_PROPERTY, "RIGHT_DS_READ_PROPERTY"},
	{RIGHT_DS_WRITE_PROPERTY, "RIGHT_DS_WRITE_PROPERTY"},
	{RIGHT_DS_DELETE_TREE, "RIGHT_DS_DELETE_TREE"},
	{RIGHT_DS_LIST_OBJECT, "RIGHT_DS_LIST_OBJECT"},
	{RIGHT_DS_CONTROL_ACCESS, "RIGHT_DS_CONTROL_ACCESS"},
	{RIGHT_DELETE, "RIGHT_DELETE"},
	{RIGHT_READ_CONTROL, "RIGHT_READ_CONTROL"},
	{RIGHT_WRITE_DAC, "RIGHT_WRITE_DAC"},
	{RIGHT_WRITE_OWNER, "RIGHT_WRITE_OWNER"},
	{RIGHT_GENERIC_ALL, "RIGHT_GENERIC_ALL"},
	{RIGHT_GENERIC_EXECUTE, "RIGHT_GENERIC_EXECUTE"},
	{RIGHT_GENERIC_WRITE, "RIGHT_GENERIC_WRITE"},
	{RIGHT_GENERIC_READ, "RIGHT_GENERIC_READ"},
}

// Names returns the names of all flags set in the mask.
func (m AccessMask) Names() []string {
	var names []string
	for _, f := range accessFlags {
		if m.Has(f.mask) {
			names = append(names, f.name)
		}
	}
	return names
}

func (m AccessMask) String() string {
	names := m.Names()
	if len(names) == 0 {
		return "0x00000000"
	}
	return strings.Join(names, "|")
}
