package ldapresolver

import "github.com/f0oster/gontsd"

// NewLDAPResolver creates a resolver backed by both well-known tables
// and LDAP queries. It preloads the schema from AD, so construction
// may take a moment on large directories.
// The caller owns the [LDAPClient] and is responsible for closing it.
func NewLDAPResolver(client *LDAPClient) (*gontsd.Resolver, error) {
	ldapGUID, err := NewLDAPSchemaGUIDResolver(client)
	if err != nil {
		return nil, err
	}

	return &gontsd.Resolver{
		SIDs: gontsd.ChainSIDResolver{
			Resolvers: []gontsd.SIDResolver{
				gontsd.WellKnownSIDResolver{},
				NewLDAPSIDResolver(client),
			},
		},
		GUIDs: gontsd.ChainSchemaGUIDResolver{
			Resolvers: []gontsd.SchemaGUIDResolver{
				gontsd.WellKnownSchemaGUIDResolver{},
				ldapGUID,
			},
		},
	}, nil
}
