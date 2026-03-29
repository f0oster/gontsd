package gontsd

// Resolver provides SID and schema GUID resolution.
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

// NewLDAPResolver creates a resolver backed by both well-known tables
// and LDAP queries. It preloads the schema from AD, so construction
// may take a moment on large directories.
// The caller owns the [LDAPClient] and is responsible for closing it.
func NewLDAPResolver(client *LDAPClient) (*Resolver, error) {
	ldapGUID, err := NewLDAPSchemaGUIDResolver(client)
	if err != nil {
		return nil, err
	}

	return &Resolver{
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
	}, nil
}
