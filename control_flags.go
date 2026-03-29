package gontsd

import "strings"

// ControlFlags represents the 16-bit control flags in a security descriptor header.
// See: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7d4dac05-9cef-4563-a058-f108abecce1d
type ControlFlags uint16

const (
	SE_OWNER_DEFAULTED       ControlFlags = 0x0001
	SE_GROUP_DEFAULTED       ControlFlags = 0x0002
	SE_DACL_PRESENT          ControlFlags = 0x0004
	SE_DACL_DEFAULTED        ControlFlags = 0x0008
	SE_SACL_PRESENT          ControlFlags = 0x0010
	SE_SACL_DEFAULTED        ControlFlags = 0x0020
	SE_DACL_AUTO_INHERIT_REQ ControlFlags = 0x0100
	SE_SACL_AUTO_INHERIT_REQ ControlFlags = 0x0200
	SE_DACL_AUTO_INHERITED   ControlFlags = 0x0400
	SE_SACL_AUTO_INHERITED   ControlFlags = 0x0800
	SE_DACL_PROTECTED        ControlFlags = 0x1000
	SE_SACL_PROTECTED        ControlFlags = 0x2000
	SE_RM_CONTROL_VALID      ControlFlags = 0x4000
	SE_SELF_RELATIVE         ControlFlags = 0x8000
)

// Has reports whether flag is set.
func (f ControlFlags) Has(flag ControlFlags) bool {
	return f&flag != 0
}

type controlFlagEntry struct {
	mask ControlFlags
	name string
}

var controlFlags = []controlFlagEntry{
	{SE_OWNER_DEFAULTED, "SE_OWNER_DEFAULTED"},
	{SE_GROUP_DEFAULTED, "SE_GROUP_DEFAULTED"},
	{SE_DACL_PRESENT, "SE_DACL_PRESENT"},
	{SE_DACL_DEFAULTED, "SE_DACL_DEFAULTED"},
	{SE_SACL_PRESENT, "SE_SACL_PRESENT"},
	{SE_SACL_DEFAULTED, "SE_SACL_DEFAULTED"},
	{SE_DACL_AUTO_INHERIT_REQ, "SE_DACL_AUTO_INHERIT_REQ"},
	{SE_SACL_AUTO_INHERIT_REQ, "SE_SACL_AUTO_INHERIT_REQ"},
	{SE_DACL_AUTO_INHERITED, "SE_DACL_AUTO_INHERITED"},
	{SE_SACL_AUTO_INHERITED, "SE_SACL_AUTO_INHERITED"},
	{SE_DACL_PROTECTED, "SE_DACL_PROTECTED"},
	{SE_SACL_PROTECTED, "SE_SACL_PROTECTED"},
	{SE_RM_CONTROL_VALID, "SE_RM_CONTROL_VALID"},
	{SE_SELF_RELATIVE, "SE_SELF_RELATIVE"},
}

// Names returns the names of all flags set.
func (f ControlFlags) Names() []string {
	var names []string
	for _, e := range controlFlags {
		if f.Has(e.mask) {
			names = append(names, e.name)
		}
	}
	return names
}

func (f ControlFlags) String() string {
	names := f.Names()
	if len(names) == 0 {
		return "0x0000"
	}
	return strings.Join(names, "|")
}
