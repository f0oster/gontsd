// Package resolve provides SID and schema GUID resolution for parsed
// security descriptors.
//
// Built-in resolvers ([WellKnownSIDResolver], [WellKnownSchemaGUIDResolver])
// cover standard Windows SIDs and common Active Directory schema GUIDs.
// For domain-specific resolution, [LDAPSIDResolver] and
// [LDAPSchemaGUIDResolver] query Active Directory using the go-ldap library.
//
// The [SIDResolver] and [SchemaGUIDResolver] interfaces are the primary
// extension points. If your project uses a different LDAP client, implement
// these interfaces directly rather than depending on the built-in LDAP
// resolvers.
package resolve
