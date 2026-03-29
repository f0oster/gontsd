# gontsd

A pure Go library for parsing, comparing, and resolving Windows NT Security Descriptors.

This library is designed around parsing Active Directory's `ntSecurityDescriptor` attribute, but any binary based security descriptor that follows the [MS-DTYP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/) standard should work for parsing and comparison.

Currently, there is no support for SDDL in the library. It may be added later.


## Quick start

```go
// Parse a binary security descriptor and resolve object names using the default, non-LDAP connected resolver.
// The default resolver covers well-known SIDs and common AD schema GUIDs.
// For Active Directory security descriptors, use gontsd.NewLDAPResolver()
// instead for full domain-specific resolution - see the Resolution section.
r := gontsd.NewResolver()
sd, err := gontsd.Parse(data, r)
if err != nil {
    log.Fatal(err)
}

// Display the owner and each ACE in the DACL
fmt.Println("Owner:", sd.OwnerSID.Resolved())
for _, ace := range sd.DACL.ACEs {
    fmt.Printf("  %s %s %s\n", ace.Type(), ace.SID().Resolved(), ace.Mask())
}
```

Output:
```
Owner: BUILTIN\Administrators (S-1-5-32-544)
  AccessDenied Everyone (S-1-1-0) RIGHT_DS_DELETE_CHILD
  AccessAllowed Everyone (S-1-1-0) RIGHT_DS_READ_PROPERTY
  AccessAllowedObject Domain Admins (S-1-5-21-...-512) RIGHT_DS_CONTROL_ACCESS
```

To resolve SIDs and GUIDs that are not a part of the Well-Known SID or Object lists, such as objects and GUIDs unique to a domain, you must pass an LDAP-backed resolver instead of `NewResolver()` - see [Resolution](#resolution) below.

## Install

```bash
go get github.com/f0oster/gontsd
```

## Parsing

`Parse` takes raw security descriptor bytes and an optional `*Resolver`. Pass `nil` to skip resolution:

```go
sd, err := gontsd.Parse(data, nil) // no resolution
sd, err := gontsd.Parse(data, r)   // with resolution
```

The returned `SecurityDescriptor` contains:

- `OwnerSID`, `GroupSID` - who owns the object
- `ControlFlags` - descriptor-level flags (DACL present, auto-inherited, self-relative, etc.)
- `DACL` - Discretionary ACL: who is allowed/denied access
- `SACL` - System ACL: what gets audited

Each ACE in the DACL/SACL exposes:

```go
ace.Type()                  // AccessAllowed, AccessDenied, AccessAllowedObject, etc.
ace.SID()                   // the trustee (who this ACE applies to)
ace.Mask()                  // what permissions are granted/denied
ace.AceFlags()              // inheritance and audit flags
ace.ObjectTypeGUID()        // which schema property/right this applies to (object ACEs only)
ace.InheritedObjectTypeGUID() // which child class inherits this ACE
```

When parsed with a resolver, SIDs and GUIDs gain a `.Resolved()` method that returns human-readable names. `.String()` always returns the raw value:

```go
ace.SID().String()            // "S-1-5-32-544"
ace.SID().Resolved()          // "BUILTIN\Administrators (S-1-5-32-544)"

guid := ace.ObjectTypeGUID()
guid.String()                 // "00299570-246D-11D0-A768-00AA006E0529"
guid.Resolved()               // "User-Force-Change-Password"
guid.Type                     // "extendedRight"
guid.Description              // "Reset a user's password without knowing the current password."
```

`AccessMask`, `ACEFlags`, and `ControlFlags` are typed bitmasks with `Has()`, `Names()`, and `String()` methods:

```go
ace.Mask().Has(gontsd.RIGHT_DS_CONTROL_ACCESS) // true/false
ace.AceFlags().Has(gontsd.INHERITED_ACE)       // true/false
ace.Mask().Names()                              // []string{"RIGHT_DS_READ_PROPERTY", ...}
```

## Comparing

`Compare` detects changes between two security descriptors - useful for auditing permission changes over time:

```go
oldSD, _ := gontsd.Parse(oldData, r)
newSD, _ := gontsd.Parse(newData, r)
diff := gontsd.Compare(oldSD, newSD)

if diff.OwnerChanged {
    fmt.Printf("Owner: %s -> %s\n", diff.OldOwner.Resolved(), diff.NewOwner.Resolved())
}

if diff.DACLDiff != nil {
    for _, d := range diff.DACLDiff.ACEDiffs {
        if d.Type.Has(gontsd.DiffAdded) {
            fmt.Printf("[+] %s %s\n", d.NewACE.SID().Resolved(), d.NewACE.Mask())
        }
        if d.Type.Has(gontsd.DiffModified) {
            added, removed, _ := d.CompareAccessRights()
            fmt.Printf("[~] %s +%v -%v\n", d.NewACE.SID().Resolved(), added, removed)
        }
    }
}
```

`DiffType` is a bitmask - an ACE that is both modified and moved will have `DiffModified | DiffReordered` set.

## Resolution

`NewResolver()` uses built-in tables to resolve common SIDs and schema GUIDs without needing to query the LDAP directory. It covers:

- **Well-known SIDs** - `BUILTIN\Administrators`, `Domain Admins`, `Everyone`, `Local System`, etc.
- **Extended rights** - `User-Force-Change-Password`, `DS-Replication-Get-Changes-All` (DCSync), `Certificate-Enrollment`, etc.
- **Validated writes** - `Validated-SPN`, `Validated-DNS-Host-Name`, `Self-Membership`
- **Property sets** - `Domain-Password`, `User-Account-Restrictions`, `Personal-Information`, etc.
- **Schema classes** - `User`, `Computer`, `Group`, `Organizational-Unit`, `Group-Policy-Container`, etc.
- **Attributes** - `member`, `servicePrincipalName`, `msDS-KeyCredentialLink`, `userAccountControl`, etc.

Domain-specific accounts, custom schema extensions, and GUIDs not in the built-in tables require LDAP resolution.

For full resolution against Active Directory, use `NewLDAPResolver`:

```go
client, err := gontsd.NewLDAPClient(gontsd.LDAPConfig{
    Server:   "ldaps://dc.example.com:636",
    BaseDN:   "DC=example,DC=com",
    BindDN:   "user@example.com",
    Password: "password",
})
if err != nil {
    log.Fatal(err)
}
defer client.Close()

r, err := gontsd.NewLDAPResolver(client)
if err != nil {
    log.Fatal(err)
}

sd, err := gontsd.Parse(data, r)
```

Resolution is automatic - `Parse` batch-resolves all SIDs upfront and stores the resolver on each SID and GUID. The results flow through `Compare` too, since the diff references the same SID/GUID pointers from the parsed descriptors.

The built-in LDAP resolvers use [go-ldap](https://github.com/go-ldap/ldap). If your project uses a different LDAP client, implement the `SIDResolver` and `SchemaGUIDResolver` interfaces directly.

## Examples

- **[dump](./examples/dump)** - fetch and display a resolved security descriptor from AD
- **[compare](./examples/compare)** - compare security descriptor snapshots and display the diff

```bash
go run ./examples/dump \
  -ldap-server "ldaps://dc.example.com:636" \
  -ldap-basedn "DC=example,DC=com" \
  -ldap-binddn "user@example.com" \
  -ldap-password "password" \
  -object-dn "DC=example,DC=com"
```

## API Reference

### Core functions

| Function | Description |
|----------|-------------|
| `Parse(data, r)` | Parse binary security descriptor bytes, optionally resolving SIDs and GUIDs |
| `Compare(old, new)` | Diff two security descriptors |
| `NewResolver()` | Create a resolver using built-in well-known tables |
| `NewLDAPResolver(client)` | Create a resolver backed by Active Directory |
| `NewLDAPClient(config)` | Establish an LDAP connection for use with `NewLDAPResolver` |

### Types

| Type | Description |
|------|-------------|
| `SecurityDescriptor` | Parsed security descriptor (owner, group, DACL, SACL) |
| `ACL` | Access control list containing ACE entries |
| `ACE` | Interface for access control entries |
| `SID` | Security identifier with `String()` and `Resolved()` |
| `GUID` | Schema GUID with `String()`, `Resolved()`, `Name`, `Type`, `Description` |
| `Resolver` | Holds SID and GUID resolvers |
| `LDAPClient` | LDAP connection wrapper |
| `LDAPConfig` | LDAP connection settings |
| `DiffResult` | Result of comparing two security descriptors |
| `ACEDiff` | Single ACE change with `CompareAccessRights()` |

### Typed bitmasks

All have `Has(flag)`, `Names()`, and `String()` methods.

| Type | Description |
|------|-------------|
| `AccessMask` | Permission flags (`RIGHT_DS_READ_PROPERTY`, `RIGHT_WRITE_DAC`, etc.) |
| `ACEFlags` | Inheritance and audit flags (`INHERITED_ACE`, `CONTAINER_INHERIT_ACE`, etc.) |
| `ControlFlags` | SD-level flags (`SE_DACL_PRESENT`, `SE_SELF_RELATIVE`, etc.) |
| `DiffType` | Change types (`DiffAdded`, `DiffRemoved`, `DiffModified`, `DiffReordered`) |

### Interfaces

| Interface | Method | Description |
|-----------|--------|-------------|
| `SIDResolver` | `Resolve(sid) (name, error)` | Resolve a SID to a display name |
| `SchemaGUIDResolver` | `ResolveGUID(guid) (*SchemaGUIDInfo, error)` | Resolve a GUID to schema metadata |

## References

- [MS-DTYP: Security Descriptor Structures](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/) - the ntSecurityDescriptor binary format
- [Well-known SIDs](https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids) - built-in Windows security identifiers
- [Extended Rights Reference](https://learn.microsoft.com/en-us/windows/win32/adschema/extended-rights) - AD Control Access Rights
- [Control Access Rights](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1522b774-6464-41a3-87a5-1e5633c3fbbb) - MS-ADTS specification for extended rights and validated writes

## License

MIT
