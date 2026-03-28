package gontsd

const (
	RIGHT_DS_CREATE_CHILD            = 0x00000001 // CC: Create child objects.
	RIGHT_DS_DELETE_CHILD            = 0x00000002 // DC: Delete child objects.
	RIGHT_DS_LIST_CONTENTS           = 0x00000004 // LC: List child objects.
	RIGHT_DS_WRITE_PROPERTY_EXTENDED = 0x00000008 // VW: Validated write operation.
	RIGHT_DS_READ_PROPERTY           = 0x00000010 // RP: Read properties of the object.
	RIGHT_DS_WRITE_PROPERTY          = 0x00000020 // WP: Write properties of the object.
	RIGHT_DS_DELETE_TREE             = 0x00000040 // DT: Delete-Tree operation.
	RIGHT_DS_LIST_OBJECT             = 0x00000080 // LO: List a particular object.
	RIGHT_DS_CONTROL_ACCESS          = 0x00000100 // CR: Perform operations controlled by a control access right.
	RIGHT_DELETE                     = 0x00010000 // DE: Delete the object.
	RIGHT_READ_CONTROL               = 0x00020000 // RC: Read data from the security descriptor.
	RIGHT_WRITE_DAC                  = 0x00040000 // WD: Modify the DACL in the security descriptor.
	RIGHT_WRITE_OWNER                = 0x00080000 // WO: Modify the owner of an object.
	RIGHT_GENERIC_ALL                = 0x10000000 // GA: Full access rights.
	RIGHT_GENERIC_EXECUTE            = 0x20000000 // GX: Read permissions and list container contents.
	RIGHT_GENERIC_WRITE              = 0x40000000 // GW: Write properties and perform validated writes.
	RIGHT_GENERIC_READ               = 0x80000000 // GR: Read permissions and properties, and list object names.
)

type flagEntry struct {
	mask uint32
	name string
}

var accessFlags = []flagEntry{
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

// CheckFlags returns a list of flag names that are set in the given mask.
func CheckFlags(mask uint32) []string {
	var setFlags []string
	for _, f := range accessFlags {
		if mask&f.mask != 0 {
			setFlags = append(setFlags, f.name)
		}
	}
	return setFlags
}
