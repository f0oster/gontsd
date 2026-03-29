# gontsd

A pure Go library for parsing, comparing, and resolving Windows NT Security Descriptors. Primarily focused on Active Directory security descriptors (`ntSecurityDescriptor`), but any implementation that follows the MS-DTYP standard (e.g. NTFS permissions) should work for parsing and comparison. Name resolution for SIDs and schema GUIDs beyond the built-in well-known tables requires Active Directory.

## Install

```bash
go get github.com/f0oster/gontsd
```

## Parsing

`Parse` takes the raw bytes of an NT security descriptor and an optional resolver. When a resolver is provided, all SIDs and GUIDs are resolved automatically:

```go
// Parse without resolution
sd, err := gontsd.Parse(data, nil)

// Parse with built-in well-known tables
r := gontsd.NewResolver()
sd, err := gontsd.Parse(data, r)

// Parse with LDAP resolution
client, _ := ldapresolver.NewLDAPClient(ldapresolver.LDAPConfig{...})
defer client.Close()
r, _ := ldapresolver.NewLDAPResolver(client)
sd, err := gontsd.Parse(data, &r.Resolver)
```

Once parsed, the security descriptor exposes the owner, group, control flags, DACL, and SACL:

```go
fmt.Println(sd.OwnerSID)           // S-1-5-32-544
fmt.Println(sd.OwnerSID.Resolved()) // BUILTIN\Administrators (S-1-5-32-544)
fmt.Println(sd.ControlFlags)        // SE_DACL_PRESENT|SE_DACL_AUTO_INHERITED|SE_SELF_RELATIVE

for _, ace := range sd.DACL.ACEs {
    fmt.Printf("%s %s %s\n", ace.Type(), ace.SID().Resolved(), ace.Mask())
    // AccessAllowed Local System (S-1-5-18) RIGHT_GENERIC_ALL

    if guid := ace.ObjectTypeGUID(); guid != nil {
        fmt.Println(guid.Resolved()) // User-Force-Change-Password
    }
}
```

`AccessMask`, `ACEFlags`, and `ControlFlags` are typed bitmasks with `Has()`, `Names()`, and `String()` methods:

```go
if ace.Mask().Has(gontsd.RIGHT_DS_CONTROL_ACCESS) {
    fmt.Println("has control access")
}

if ace.AceFlags().Has(gontsd.INHERITED_ACE) {
    fmt.Println("inherited from parent")
}
```

## Comparing

`Compare` detects changes between two security descriptors. If the SDs were parsed with a resolver, the diff results are automatically resolved too:

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

`DiffType` is a bitmask — an ACE that is both modified and moved will have `DiffModified | DiffReordered` set.

## Resolution

SIDs and GUIDs carry their resolver internally after `Parse`. Call `.Resolved()` anywhere to get the human-readable name, or `.String()` for the raw value:

```go
sid.String()    // "S-1-5-32-544"
sid.Resolved()  // "BUILTIN\Administrators (S-1-5-32-544)"

guid.String()   // "00299570-246D-11D0-A768-00AA006E0529"
guid.Resolved() // "User-Force-Change-Password"
```

`NewResolver()` provides built-in well-known tables. For domain-specific SIDs and custom schema objects, use the `ldapresolver` sub-package:

```go
import "github.com/f0oster/gontsd/ldapresolver"

client, err := ldapresolver.NewLDAPClient(ldapresolver.LDAPConfig{
    Server:   "ldaps://dc.example.com:636",
    BaseDN:   "DC=example,DC=com",
    BindDN:   "user@example.com",
    Password: "password",
})
if err != nil {
    log.Fatal(err)
}
defer client.Close()

r, err := ldapresolver.NewLDAPResolver(client)
if err != nil {
    log.Fatal(err)
}

sd, err := gontsd.Parse(data, &r.Resolver)
```

The built-in LDAP resolvers use [go-ldap](https://github.com/go-ldap/ldap). If your project uses a different LDAP client, you can implement the `SIDResolver` and `SchemaGUIDResolver` interfaces directly.

## Examples

Examples in the [examples](./examples) directory:

- **[dump](./examples/dump)** — fetch and display a resolved security descriptor from AD
- **[compare](./examples/compare)** — compare security descriptor snapshots and display the diff

```bash
# Dump a security descriptor from AD
go run ./examples/dump \
  -ldap-server "ldaps://dc.example.com:636" \
  -ldap-basedn "DC=example,DC=com" \
  -ldap-binddn "user@example.com" \
  -ldap-password "password" \
  -object-dn "DC=example,DC=com"

# Compare two descriptor snapshots
go run ./examples/compare \
  -ldap-server "ldaps://dc.example.com:636" \
  -ldap-basedn "DC=example,DC=com" \
  -ldap-binddn "user@example.com" \
  -ldap-password "password"
```

## License

MIT
