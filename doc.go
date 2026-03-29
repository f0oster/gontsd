// Package gontsd parses, compares, and resolves Windows NT Security
// Descriptors as defined in the MS-DTYP specification.
//
// Pass a [*Resolver] to [Parse] to resolve SIDs and GUIDs to
// human-readable names. Use [NewResolver] for built-in well-known
// tables, or the [ldapresolver] sub-package for Active Directory lookups.
//
// References:
//   - MS-DTYP (Security Descriptor structure): https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/
//   - Well-known SIDs: https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids
//   - Extended rights: https://learn.microsoft.com/en-us/windows/win32/adschema/extended-rights
//   - Control access rights: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1522b774-6464-41a3-87a5-1e5633c3fbbb
package gontsd
