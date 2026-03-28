package gontsd

// ACE inheritance and audit flags.
// See: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586
const (
	OBJECT_INHERIT_ACE         = 0x01 // OI: ACE is inherited by non-container child objects.
	CONTAINER_INHERIT_ACE      = 0x02 // CI: ACE is inherited by container child objects.
	NO_PROPAGATE_INHERIT_ACE   = 0x04 // NP: Inheritance is blocked after one level.
	INHERIT_ONLY_ACE           = 0x08 // IO: ACE does not apply to the object itself, only inherited.
	INHERITED_ACE              = 0x10 // ID: ACE was inherited from a parent object.
	SUCCESSFUL_ACCESS_ACE_FLAG = 0x40 // SA: Generate audit on successful access (SACL only).
	FAILED_ACCESS_ACE_FLAG     = 0x80 // FA: Generate audit on failed access (SACL only).
)

type aceFlagEntry struct {
	mask uint8
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

// CheckAceFlags returns a list of flag names that are set in the given ACE flags byte.
func CheckAceFlags(flags uint8) []string {
	var set []string
	for _, f := range aceFlags {
		if flags&f.mask != 0 {
			set = append(set, f.name)
		}
	}
	return set
}
