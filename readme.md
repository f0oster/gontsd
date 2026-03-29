# gontsd

A pure Go library for parsing, comparing, and resolving Windows NT Security Descriptors. Primarily focused on Active Directory security descriptors (`ntSecurityDescriptor`), but any implementation that follows the MS-DTYP standard (e.g. NTFS permissions) should work for parsing and comparison. Name resolution for SIDs and schema GUIDs beyond the built-in well-known tables requires Active Directory.

## Install

```bash
go get github.com/f0oster/gontsd
```

## Parsing

`Parse` takes the raw bytes of an NT security descriptor and returns the owner, group, control flags, DACL, and SACL:

```go
// data is the raw binary ntSecurityDescriptor, e.g. from an LDAP query
sd, err := gontsd.Parse(data)
if err != nil {
    log.Fatal(err)
}

fmt.Println(sd.OwnerSID)    // S-1-5-32-544
fmt.Println(sd.ControlFlags) // SE_DACL_PRESENT|SE_DACL_AUTO_INHERITED|SE_SELF_RELATIVE

// Walk the DACL to inspect each access control entry
for _, ace := range sd.DACL.ACEs {
    fmt.Printf("%s %s %s\n", ace.Type(), ace.SID(), ace.Mask())
    // AccessAllowed S-1-5-18 RIGHT_GENERIC_ALL
    // AccessAllowedObject S-1-5-32-544 RIGHT_DS_CONTROL_ACCESS

    // Object ACEs scope permissions to a specific schema class or property
    if guid := ace.ObjectTypeGUID(); guid != "" {
        fmt.Printf("  applies to: %s\n", guid)
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

`Compare` detects changes between two security descriptors, including owner, group, control flags, and individual ACE changes in the DACL and SACL:

```go
diff := gontsd.Compare(oldSD, newSD)

if diff.OwnerChanged {
    fmt.Printf("Owner: %s -> %s\n", diff.OldOwner, diff.NewOwner)
}

if diff.DACLDiff != nil {
    for _, d := range diff.DACLDiff.ACEDiffs {
        if d.Type.Has(gontsd.DiffAdded) {
            fmt.Printf("[+] %s %s\n", d.NewACE.SID(), d.NewACE.Mask())
        }
        if d.Type.Has(gontsd.DiffRemoved) {
            fmt.Printf("[-] %s %s\n", d.OldACE.SID(), d.OldACE.Mask())
        }
        if d.Type.Has(gontsd.DiffModified) {
            added, removed, _ := d.CompareAccessRights()
            fmt.Printf("[~] %s +%v -%v\n", d.NewACE.SID(), added, removed)
        }
    }
}
```

`DiffType` is a bitmask — an ACE that is both modified and moved will have `DiffModified | DiffReordered` set.

## SID and GUID Resolution

The `resolve` package translates raw SIDs and schema GUIDs into human-readable names. Use `NewResolver()` for built-in well-known tables, or `NewLDAPResolver()` to also query Active Directory for domain-specific SIDs and custom schema objects.

```go
// Connect to AD
client, err := resolve.NewLDAPClient(resolve.LDAPConfig{
    Server:   "ldaps://dc.example.com:636",
    BaseDN:   "DC=example,DC=com",
    BindDN:   "user@example.com",
    Password: "password",
})
if err != nil {
    log.Fatal(err)
}
defer client.Close()

// Create a resolver that checks built-in tables first, then falls back to LDAP
r, err := resolve.NewLDAPResolver(client)
if err != nil {
    log.Fatal(err)
}

// Parse a security descriptor
sd, err := gontsd.Parse(rawBytes)
if err != nil {
    log.Fatal(err)
}

// Batch-resolve all SIDs upfront to minimise LDAP round-trips
resolve.ResolveBatchSIDs(r.SIDs, sd.CollectSIDs())

// Display resolved names
fmt.Println(resolve.FormatSID(sd.OwnerSID, r.SIDs))
// "BUILTIN\Administrators (S-1-5-32-544)"

for _, ace := range sd.DACL.ACEs {
    fmt.Println(resolve.FormatSID(ace.SID(), r.SIDs))
    // "Domain Admins (S-1-5-21-....-512)"

    if guid := ace.ObjectTypeGUID(); guid != "" {
        fmt.Println(resolve.FormatGUID(guid, r.GUIDs))
        // "User-Force-Change-Password"
    }
}
```

If you don't have LDAP access, `resolve.NewResolver()` provides the same interface using only the built-in tables. SIDs and GUIDs not in those tables will remain unresolved.

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
