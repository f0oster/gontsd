// Example: Resolving SIDs and GUIDs via LDAP
//
// Usage:
//
//	go run ./examples/resolve <sd-binary-file> \
//	  -server "ldaps://dc.example.com:636" \
//	  -basedn "DC=example,DC=com" \
//	  -binddn "CN=user,DC=example,DC=com" \
//	  -password "password"
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/f0oster/gontsd"
	"github.com/f0oster/gontsd/resolve"
)

func main() {
	server := flag.String("server", "", "LDAP server URL")
	baseDN := flag.String("basedn", "", "Base DN")
	bindDN := flag.String("binddn", "", "Bind DN")
	password := flag.String("password", "", "Password")
	insecure := flag.Bool("insecure", false, "Skip TLS certificate verification")
	flag.Parse()

	if flag.NArg() < 1 || *server == "" {
		fmt.Fprintf(os.Stderr, "usage: %s <sd-binary-file> -server <url> -basedn <dn> -binddn <dn> -password <pw>\n", os.Args[0])
		os.Exit(1)
	}

	data, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read file: %v\n", err)
		os.Exit(1)
	}

	sd, err := gontsd.Parse(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse: %v\n", err)
		os.Exit(1)
	}

	// Set up LDAP connection
	client, err := resolve.NewLDAPClient(resolve.LDAPConfig{
		Server:             *server,
		BaseDN:             *baseDN,
		BindDN:             *bindDN,
		Password:           *password,
		InsecureSkipVerify: *insecure,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "LDAP connection failed: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

	// Chain resolvers: well-known first, then LDAP
	sidResolver := resolve.ChainSIDResolver{
		Resolvers: []resolve.SIDResolver{
			resolve.WellKnownSIDResolver{},
			resolve.NewLDAPSIDResolver(client),
		},
	}

	ldapGUID, err := resolve.NewLDAPSchemaGUIDResolver(client)
	if err != nil {
		fmt.Fprintf(os.Stderr, "GUID resolver init failed: %v\n", err)
		os.Exit(1)
	}
	guidResolver := resolve.ChainSchemaGUIDResolver{
		Resolvers: []resolve.SchemaGUIDResolver{
			resolve.WellKnownSchemaGUIDResolver{},
			ldapGUID,
		},
	}

	// Batch-resolve all SIDs upfront
	resolve.ResolveBatchSIDs(sidResolver, sd.CollectSIDs())

	// Print resolved output
	fmt.Printf("Owner: %s\n", resolveSID(sd.OwnerSID, sidResolver))
	fmt.Printf("Group: %s\n", resolveSID(sd.GroupSID, sidResolver))

	if sd.DACL != nil {
		fmt.Printf("\nDACL (%d ACEs):\n", len(sd.DACL.ACEs))
		for i, ace := range sd.DACL.ACEs {
			fmt.Printf("\n  [%d] %sACE\n", i, ace.Type())
			fmt.Printf("      SID:    %s\n", resolveSID(ace.GetSID(), sidResolver))
			fmt.Printf("      Rights: %v\n", ace.GetAccessRights())
			if guid := ace.GetObjectTypeGUID(); guid != "" {
				fmt.Printf("      ObjectType: %s\n", resolveGUID(guid, guidResolver))
			}
			if guid := ace.GetInheritedObjectTypeGUID(); guid != "" {
				fmt.Printf("      InheritedObjectType: %s\n", resolveGUID(guid, guidResolver))
			}
		}
	}
}

func resolveSID(sid *gontsd.SID, resolver resolve.SIDResolver) string {
	if sid == nil {
		return "<nil>"
	}
	name, err := resolver.Resolve(sid)
	if err != nil {
		return sid.Parsed
	}
	return fmt.Sprintf("%s (%s)", sid.Parsed, name)
}

func resolveGUID(guid string, resolver resolve.SchemaGUIDResolver) string {
	info, err := resolver.ResolveGUID(guid)
	if err != nil {
		return guid
	}
	return fmt.Sprintf("%s (%s) [%s]", info.Name, guid, info.Type)
}
