package resolve

// Resolver provides SID and schema GUID resolution using built-in
// well-known tables. SIDs and GUIDs not in the built-in tables will
// not be resolved. For domain-specific resolution, use [LDAPResolver].
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

// LDAPResolver extends [Resolver] with Active Directory lookups,
// chaining well-known tables with LDAP queries as a fallback.
// The caller owns the [LDAPClient] and is responsible for closing it.
type LDAPResolver struct {
	Resolver
}

// NewLDAPResolver creates a resolver backed by both well-known tables
// and LDAP queries. It preloads the schema from AD, so construction
// may take a moment on large directories.
func NewLDAPResolver(client *LDAPClient) (*LDAPResolver, error) {
	ldapGUID, err := NewLDAPSchemaGUIDResolver(client)
	if err != nil {
		return nil, err
	}

	return &LDAPResolver{
		Resolver: Resolver{
			SIDs: ChainSIDResolver{
				Resolvers: []SIDResolver{
					WellKnownSIDResolver{},
					NewLDAPSIDResolver(client),
				},
			},
			GUIDs: ChainSchemaGUIDResolver{
				Resolvers: []SchemaGUIDResolver{
					WellKnownSchemaGUIDResolver{},
					ldapGUID,
				},
			},
		},
	}, nil
}
