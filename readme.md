# gontsd

A pure Go library for parsing, comparing, and resolving Windows NT Security Descriptors.

Built for Active Directory's `ntSecurityDescriptor` attribute. Binary security descriptors from other sources (ie: NTFS permissions, registry) will parse if they follow [MS-DTYP], but ACE type coverage is focused on AD - see [ACE type support](#ace-type-support) for details.

## Quick start

```go
r := gontsd.NewResolver()
sd, err := gontsd.Parse(data, r)
if err != nil {
    log.Fatal(err)
}

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
  AccessAllowedObject S-1-5-21-3623811015-3361044348-30300820-1013 RIGHT_DS_CONTROL_ACCESS
```

`NewResolver()` covers well-known SIDs and common AD schema GUIDs. Domain-specific SIDs (like the one above) require an LDAP-backed resolver - see [Resolution](#resolution). When resolution misses, `SID.Resolved()` and `GUID.Resolved()` fall back to the raw string value silently; no error is returned.

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

`Parse` returns an error on malformed input - truncated headers, invalid offsets, ACE size mismatches, or data too short for declared structures. All variable-length fields are bounds-checked. It does not return partial results: either the full descriptor parses successfully or it fails.

The returned `SecurityDescriptor` contains:

- `OwnerSID`, `GroupSID` - who owns the object
- `ControlFlags` - descriptor-level flags (DACL present, auto-inherited, self-relative, etc.)
- `DACL` - Discretionary ACL: who is allowed/denied access
- `SACL` - System ACL: what gets audited

Each ACE in the DACL/SACL exposes:

```go
ace.Type()                     // AccessAllowed, AccessDenied, AccessAllowedObject, etc.
ace.SID()                      // the trustee (who this ACE applies to)
ace.Mask()                     // what permissions are granted/denied
ace.AceFlags()                 // inheritance and audit flags
ace.ObjectTypeGUID()           // schema property/right this applies to (object ACEs only, nil otherwise)
ace.InheritedObjectTypeGUID()  // child class that inherits this ACE (object ACEs only, nil otherwise)
ace.ApplicationData()          // conditional expression bytes (callback ACEs only, nil otherwise)
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

## ACE type support

### Core ACE types

These ACE types are fully parsed into typed structs. The parser validates the ACE header, access mask, and SID, and for object ACE variants also validates and extracts ObjectType and InheritedObjectType according to the variable-length layout indicated by the ACE flags. Inheritance and audit flags are preserved. SIDs and GUIDs are resolved when a resolver is available.

| Byte | Type |
|------|------|
| 0x00 | ACCESS_ALLOWED |
| 0x01 | ACCESS_DENIED |
| 0x02 | SYSTEM_AUDIT |
| 0x05 | ACCESS_ALLOWED_OBJECT |
| 0x06 | ACCESS_DENIED_OBJECT |
| 0x07 | SYSTEM_AUDIT_OBJECT |

### Callback ACE types

These callback ACE types receive the same structural parsing and validation. ApplicationData offset and length are validated against the ACE size, and the trailing bytes are exposed as raw data. The conditional expression encoded in ApplicationData is not interpreted.

| Byte | Type |
|------|------|
| 0x09 | ACCESS_ALLOWED_CALLBACK |
| 0x0A | ACCESS_DENIED_CALLBACK |
| 0x0B | ACCESS_ALLOWED_CALLBACK_OBJECT |
| 0x0C | ACCESS_DENIED_CALLBACK_OBJECT |

### Fallback (RawACE)

All other ACE types fall back to `RawACE`. `RawACE` stores the original ACE bytes unchanged. It also performs a best-effort extraction of header, access mask, and SID using the standard access-allowed ACE layout. The header is always reliable. For ACE types with a different layout, extracted mask and SID fields may be unset.

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

`DiffType` is a bitmask - an ACE that is both modified and moved will have `DiffModified | DiffReordered` set. Comparison matches ACEs by identity (type + SID + ObjectTypeGUID), then detects position changes. `DiffReordered` means the ACE moved index but is otherwise identical.

## Resolution

`NewResolver()` resolves common SIDs and schema GUIDs from built-in lookup tables. It covers:

- **Well-known SIDs** - `BUILTIN\Administrators`, `Domain Admins`, `Everyone`, `Local System`, etc.
- **Extended rights** - `User-Force-Change-Password`, `DS-Replication-Get-Changes-All` (DCSync), `Certificate-Enrollment`, etc.
- **Validated writes** - `Validated-SPN`, `Validated-DNS-Host-Name`, `Self-Membership`
- **Property sets** - `Domain-Password`, `User-Account-Restrictions`, `Personal-Information`, etc.
- **Schema classes** - `User`, `Computer`, `Group`, `Organizational-Unit`, `Group-Policy-Container`, etc.
- **Attributes** - `member`, `servicePrincipalName`, `msDS-KeyCredentialLink`, `userAccountControl`, etc.

Domain-specific accounts, custom schema extensions, and GUIDs not in the built-in tables require LDAP resolution.

For full resolution against AD, use `NewLDAPResolver`:

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

When using an LDAP resolver, `Parse` collects all unique SIDs from the descriptor and resolves them in batched LDAP queries. Schema GUIDs are resolved individually but the LDAP schema GUID resolver preloads classes, attributes, and extended rights when it's created, so most lookups are served from cache.

Resolution results flow through `Compare` too, since the diff references the same SID/GUID objects from the parsed descriptors.

The built-in LDAP resolvers use [go-ldap]. If your project uses a different LDAP client, implement the `SIDResolver` and `SchemaGUIDResolver` interfaces and pass them to `NewResolverWith`:

```go
r := gontsd.NewResolverWith(myCustomSIDResolver{}, myCustomGUIDResolver{})
sd, err := gontsd.Parse(data, r)
```

This chains the built-in well-known tables with your custom resolvers, so well-known SIDs and schema GUIDs resolve instantly and everything else falls through to your implementation.

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
| `NewResolverWith(sids, guids)` | Create a resolver chaining built-in tables with custom resolvers |
| `NewLDAPResolver(client)` | Create a resolver backed by AD |
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

- [MS-DTYP][MS-DTYP] - Microsoft data type specification defining the binary format for security descriptors, ACLs, ACEs, and SIDs
- [Well-known SIDs][well-known-sids] - Microsoft reference for built-in security identifiers across Windows
- [Extended Rights Reference][extended-rights] - AD schema reference for extended rights and their GUIDs
- [Control Access Rights][control-access-rights] - MS-ADTS specification for how extended rights, validated writes, and property sets map to object ACE GUIDs

[MS-DTYP]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/
[go-ldap]: https://github.com/go-ldap/ldap
[well-known-sids]: https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids
[extended-rights]: https://learn.microsoft.com/en-us/windows/win32/adschema/extended-rights
[control-access-rights]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1522b774-6464-41a3-87a5-1e5633c3fbbb

## License

MIT
