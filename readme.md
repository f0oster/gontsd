# gontsd

A pure Go library for parsing, comparing, and resolving Windows NT Security Descriptors (`ntSecurityDescriptor`). No Windows APIs required.

## Install

```bash
go get github.com/f0oster/gontsd
```

## Parsing

```go
sd, err := gontsd.Parse(data)
if err != nil {
    log.Fatal(err)
}

fmt.Println(sd.OwnerSID)   // "S-1-5-32-544"
fmt.Println(sd.GroupSID)   // "S-1-5-32-544"

// DACL and SACL are both parsed when present
for _, ace := range sd.DACL.ACEs {
    fmt.Printf("%s %s %v\n", ace.Type(), ace.GetSID(), ace.GetAccessRights())
}
```

## Comparing

```go
diff := gontsd.Compare(oldSD, newSD)

if diff.HasChanges() {
    if diff.DACLDiff != nil {
        for _, d := range diff.DACLDiff.ACEDiffs {
            if d.Type.Has(gontsd.DiffAdded) {
                fmt.Printf("[+] %s\n", d.NewACE.GetSID())
            }
            if d.Type.Has(gontsd.DiffModified) {
                added, removed, _ := d.CompareAccessRights()
                fmt.Printf("[~] %s +%v -%v\n", d.NewACE.GetSID(), added, removed)
            }
        }
    }
}
```

`DiffType` is a bitmask — an ACE that is both modified and moved will have `DiffModified | DiffReordered` set.

## SID and GUID Resolution

The `resolve` package translates raw SIDs and schema GUIDs into human-readable names.

### Without LDAP

Resolve built-in Windows SIDs and well-known domain RIDs without a network connection:

```go
resolver := resolve.WellKnownSIDResolver{}
name, err := resolver.Resolve(sid) // "BUILTIN\Administrators", "Domain Admins", etc.

// Or use FormatSID for display strings:
fmt.Println(resolve.FormatSID(sid, resolver)) // "S-1-5-32-544 (BUILTIN\Administrators)"
```

Resolve well-known schema GUIDs:

```go
guidResolver := resolve.WellKnownSchemaGUIDResolver{}
info, err := guidResolver.ResolveGUID("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")
fmt.Println(info.Name, info.Type) // "DS-Replication-Get-Changes-All" "extendedRight"
```

### With LDAP

For full resolution against Active Directory, chain the well-known resolvers with LDAP-backed ones:

```go
client, err := resolve.NewLDAPClient(resolve.LDAPConfig{
    Server: "ldaps://dc.example.com:636",
    BaseDN: "DC=example,DC=com",
    BindDN: "CN=user,DC=example,DC=com",
    Password: "password",
})
if err != nil {
    log.Fatal(err)
}
defer client.Close()

// SID resolution: well-known first, then LDAP for domain-specific SIDs
sidResolver := resolve.ChainSIDResolver{
    Resolvers: []resolve.SIDResolver{
        resolve.WellKnownSIDResolver{},
        resolve.NewLDAPSIDResolver(client),
    },
}

// GUID resolution: well-known first, then LDAP schema
ldapGUID, err := resolve.NewLDAPSchemaGUIDResolver(client)
if err != nil {
    log.Fatal(err)
}
guidResolver := resolve.ChainSchemaGUIDResolver{
    Resolvers: []resolve.SchemaGUIDResolver{
        resolve.WellKnownSchemaGUIDResolver{},
        ldapGUID,
    },
}
```

### Batch SID resolution

For security descriptors with many ACEs, resolve all SIDs in bulk to minimise LDAP round-trips. Subsequent individual `Resolve` calls will hit the cache:

```go
resolve.ResolveBatchSIDs(sidResolver, sd.CollectSIDs())

// Now individual calls are cache hits
fmt.Println(resolve.FormatSID(sd.OwnerSID, sidResolver))
```

## Examples

Focused examples in the [examples](./examples) directory:

- **[parse](./examples/parse)** — parse a descriptor and inspect its contents
- **[compare](./examples/compare)** — compare two descriptors and print the diff
- **[resolve](./examples/resolve)** — resolve SIDs and GUIDs via LDAP
- **[full](./examples/full)** — comprehensive demo combining all of the above

```bash
# Parse a descriptor
go run ./examples/parse ./examples/test_cases/root_domain/sd-domainroot.bin

# Compare two descriptors
go run ./examples/compare \
  ./examples/test_cases/adding_flag/sd-filedomain_default.bin \
  ./examples/test_cases/adding_flag/sd-filedomain_change.bin

# Full demo with LDAP
go run ./examples/full \
  -ldap-server "ldaps://dc.example.com:636" \
  -ldap-basedn "DC=example,DC=com" \
  -ldap-binddn "CN=user,DC=example,DC=com" \
  -ldap-password "password"
```

## License

MIT
