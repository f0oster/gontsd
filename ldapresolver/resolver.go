package ldapresolver

import "github.com/f0oster/gontsd"

// LDAPResolver extends [gontsd.Resolver] with Active Directory lookups,
// chaining well-known tables with LDAP queries as a fallback.
// The caller owns the [LDAPClient] and is responsible for closing it.
type LDAPResolver struct {
	gontsd.Resolver
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
		Resolver: gontsd.Resolver{
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
		},
	}, nil
}
