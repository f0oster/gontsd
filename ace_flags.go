package gontsd

// ACEFlags represents the 8-bit inheritance and audit flags in an ACE header.
// See: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586
type ACEFlags uint8

const (
	OBJECT_INHERIT_ACE         ACEFlags = 0x01 // OI: ACE is inherited by non-container child objects.
	CONTAINER_INHERIT_ACE      ACEFlags = 0x02 // CI: ACE is inherited by container child objects.
	NO_PROPAGATE_INHERIT_ACE   ACEFlags = 0x04 // NP: Inheritance is blocked after one level.
	INHERIT_ONLY_ACE           ACEFlags = 0x08 // IO: ACE does not apply to the object itself, only inherited.
	INHERITED_ACE              ACEFlags = 0x10 // ID: ACE was inherited from a parent object.
	SUCCESSFUL_ACCESS_ACE_FLAG ACEFlags = 0x40 // SA: Generate audit on successful access (SACL only).
	FAILED_ACCESS_ACE_FLAG     ACEFlags = 0x80 // FA: Generate audit on failed access (SACL only).
)

// Has reports whether flag is set.
func (f ACEFlags) Has(flag ACEFlags) bool {
	return f&flag != 0
}

type aceFlagEntry struct {
	mask ACEFlags
	name string
}

var aceFlags = []aceFlagEntry{
	{OBJECT_INHERIT_ACE, "OBJECT_INHERIT_ACE"},
	{CONTAINER_INHERIT_ACE, "CONTAINER_INHERIT_ACE"},
	{NO_PROPAGATE_INHERIT_ACE, "NO_PROPAGATE_INHERIT_ACE"},
	{INHERIT_ONLY_ACE, "INHERIT_ONLY_ACE"},
	{INHERITED_ACE, "INHERITED_ACE"},
	{SUCCESSFUL_ACCESS_ACE_FLAG, "SUCCESSFUL_ACCESS_ACE_FLAG"},
	{FAILED_ACCESS_ACE_FLAG, "FAILED_ACCESS_ACE_FLAG"},
}

// Names returns the names of all flags set.
func (f ACEFlags) Names() []string {
	var names []string
	for _, e := range aceFlags {
		if f.Has(e.mask) {
			names = append(names, e.name)
		}
	}
	return names
}
