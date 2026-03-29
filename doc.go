// Package gontsd parses, compares, and resolves Windows NT Security
// Descriptors as defined in the MS-DTYP specification.
//
// Pass a [*Resolver] to [Parse] to resolve SIDs and GUIDs to
// human-readable names. Use [NewResolver] for built-in well-known
// tables, or the [ldapresolver] sub-package for Active Directory lookups.
package gontsd
