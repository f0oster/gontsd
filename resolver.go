package gontsd

// Resolver provides SID and schema GUID resolution using built-in
// well-known tables. SIDs and GUIDs not in the built-in tables will
// not be resolved. For domain-specific resolution, use the ldap sub-package.
type Resolver struct {
	SIDs  SIDResolver
	GUIDs SchemaGUIDResolver
}

// NewResolver returns a resolver using the built-in well-known SID
// and schema GUID tables.
func NewResolver() *Resolver {
	return &Resolver{
		SIDs:  WellKnownSIDResolver{},
		GUIDs: WellKnownSchemaGUIDResolver{},
	}
}
