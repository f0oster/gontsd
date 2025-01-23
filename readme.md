# gontsd

A Go parser for Windows NT Security Descriptors (`ntSecurityDescriptor`). Platform independent.

## Install

```bash
go get github.com/f0oster/gontsd
```

## Usage

```go
import "github.com/f0oster/gontsd"

// Parse binary security descriptor
sd, err := gontsd.Parse(data)

// Access parsed fields
fmt.Println(sd.OwnerSID)
fmt.Println(sd.GroupSID)
fmt.Println(sd.DACL)
```

## Comparing Security Descriptors

```go
diff := gontsd.Compare(oldSD, newSD)

if diff.HasChanges() {
    if diff.OwnerChanged {
        fmt.Printf("Owner: %s -> %s\n", diff.OldOwner, diff.NewOwner)
    }

    if diff.DACLDiff != nil {
        for _, aceDiff := range diff.DACLDiff.ACEDiffs {
            switch aceDiff.Type {
            case gontsd.DiffAdded:
                fmt.Printf("Added: %s\n", aceDiff.NewACE.GetSID())
            case gontsd.DiffRemoved:
                fmt.Printf("Removed: %s\n", aceDiff.OldACE.GetSID())
            case gontsd.DiffModified:
                fmt.Printf("Modified: %s\n", aceDiff.NewACE.GetSID())
            }
        }
    }
}
```

## SID & GUID Resolution

The `resolve` package provides resolvers for translating SIDs and schema GUIDs to human-readable names.

Requires [go-ldap](https://github.com/go-ldap/ldap) for LDAP resolution.

```go
import "github.com/f0oster/gontsd/resolve"

// Well-known SIDs (no LDAP required)
resolver := resolve.WellKnownSIDResolver{}
name, _ := resolver.Resolve(sid) // "BUILTIN\Administrators"

// LDAP resolver for domain SIDs
ldapResolver, _ := resolve.NewLDAPSIDResolver(resolve.LDAPConfig{
    Server:   "ldap://dc.example.com:389",
    BaseDN:   "DC=example,DC=com",
    BindDN:   "CN=user,DC=example,DC=com",
    Password: "password",
})
defer ldapResolver.Close()

name, _ := ldapResolver.Resolve(sid) // "DOMAIN\username"
```

## Examples

See the [examples](./examples) directory for a complete working example including:
- Parsing and dumping security descriptors
- Comparing two security descriptors
- SID and GUID resolution with LDAP

```bash
# Run with well-known SIDs only
go run ./examples

# Run with LDAP resolution
go run ./examples \
  -ldap-server "ldap://dc.example.com:389" \
  -ldap-basedn "DC=example,DC=com" \
  -ldap-binddn "CN=user,DC=example,DC=com" \
  -ldap-password "password"
```

## License

MIT
