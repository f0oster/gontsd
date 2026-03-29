// Full example demonstrating parsing, comparing, and resolving
// NT Security Descriptors with optional LDAP support.
//
// Run from the repository root:
//
//	go run ./examples/full
//	go run ./examples/full -ldap-server "ldaps://dc.example.com:636" ...
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/f0oster/gontsd"
	"github.com/f0oster/gontsd/resolve"
)

func main() {
	ldapServer := flag.String("ldap-server", "", "LDAP server URL (e.g., ldap://dc.example.com:389)")
	ldapBaseDN := flag.String("ldap-basedn", "", "LDAP base DN (e.g., DC=example,DC=com)")
	ldapBindDN := flag.String("ldap-binddn", "", "LDAP bind DN")
	ldapPassword := flag.String("ldap-password", "", "LDAP password")
	ldapTLS := flag.Bool("ldap-tls", false, "Use STARTTLS")
	ldapInsecure := flag.Bool("ldap-insecure", false, "Skip TLS certificate verification")
	flag.Parse()

	var resolver resolve.SIDResolver = resolve.WellKnownSIDResolver{}
	var guidResolver resolve.SchemaGUIDResolver = resolve.WellKnownSchemaGUIDResolver{}

	if *ldapServer != "" {
		client, err := resolve.NewLDAPClient(resolve.LDAPConfig{
			Server:             *ldapServer,
			BaseDN:             *ldapBaseDN,
			BindDN:             *ldapBindDN,
			Password:           *ldapPassword,
			UseTLS:             *ldapTLS,
			InsecureSkipVerify: *ldapInsecure,
		})
		if err != nil {
			fmt.Printf("Warning: Failed to connect to LDAP: %v\n", err)
		} else {
			defer client.Close()
			resolver = resolve.ChainSIDResolver{
				Resolvers: []resolve.SIDResolver{
					resolve.WellKnownSIDResolver{},
					resolve.NewLDAPSIDResolver(client),
				},
			}

			ldapGUIDResolver, err := resolve.NewLDAPSchemaGUIDResolver(client)
			if err != nil {
				fmt.Printf("Warning: Failed to create LDAP GUID resolver: %v\n", err)
			} else {
				guidResolver = resolve.ChainSchemaGUIDResolver{
					Resolvers: []resolve.SchemaGUIDResolver{
						resolve.WellKnownSchemaGUIDResolver{},
						ldapGUIDResolver,
					},
				}
			}
		}
	}

	runComparisons(resolver, guidResolver)
	dumpSecurityDescriptor("../test_cases/root_domain/sd-domainroot.bin", resolver, guidResolver)
}

func runComparisons(resolver resolve.SIDResolver, guidResolver resolve.SchemaGUIDResolver) {
	fmt.Println()
	fmt.Println("=== Comparisons ===")

	comparisons := []struct {
		Name    string
		OldPath string
		NewPath string
	}{
		{
			Name:    "Added Principal To ACE",
			OldPath: "../test_cases/adding_new_user/sd-filedomain_default.bin",
			NewPath: "../test_cases/adding_new_user/sd-filedomain_change.bin",
		},
		{
			Name:    "Removed Flag From ACE",
			OldPath: "../test_cases/removing_flag/sd-filedomain_default.bin",
			NewPath: "../test_cases/removing_flag/sd-filedomain_change.bin",
		},
		{
			Name:    "Added Flag To ACE",
			OldPath: "../test_cases/adding_flag/sd-filedomain_default.bin",
			NewPath: "../test_cases/adding_flag/sd-filedomain_change.bin",
		},
	}

	for _, c := range comparisons {
		fmt.Printf("\n=== %s ===\n", c.Name)

		oldData, err := os.ReadFile(c.OldPath)
		if err != nil {
			fmt.Printf("Failed to read old file: %v\n", err)
			continue
		}

		newData, err := os.ReadFile(c.NewPath)
		if err != nil {
			fmt.Printf("Failed to read new file: %v\n", err)
			continue
		}

		oldSD, err := gontsd.Parse(oldData)
		if err != nil {
			fmt.Printf("Failed to parse old SD: %v\n", err)
			continue
		}

		newSD, err := gontsd.Parse(newData)
		if err != nil {
			fmt.Printf("Failed to parse new SD: %v\n", err)
			continue
		}

		// Batch-resolve all SIDs from both descriptors upfront.
		resolve.ResolveBatchSIDs(resolver, append(oldSD.CollectSIDs(), newSD.CollectSIDs()...))

		diff := gontsd.Compare(oldSD, newSD)
		printDiff(diff, resolver, guidResolver)
	}
}

func dumpSecurityDescriptor(path string, resolver resolve.SIDResolver, guidResolver resolve.SchemaGUIDResolver) {
	fmt.Println()
	fmt.Printf("=== Security Descriptor Dump: %s ===\n", path)

	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("Failed to read file: %v\n", err)
		return
	}

	sd, err := gontsd.Parse(data)
	if err != nil {
		fmt.Printf("Failed to parse SD: %v\n", err)
		return
	}

	// Batch-resolve all SIDs upfront so individual lookups are cache hits.
	resolve.ResolveBatchSIDs(resolver, sd.CollectSIDs())

	fmt.Printf("\nOwner: %s\n", resolve.FormatSID(sd.OwnerSID, resolver))
	fmt.Printf("Group: %s\n", resolve.FormatSID(sd.GroupSID, resolver))
	fmt.Printf("Control: %s\n", sd.ControlFlags)

	if sd.DACL != nil {
		fmt.Printf("\nDACL (%d ACEs):\n", len(sd.DACL.ACEs))
		for i, ace := range sd.DACL.ACEs {
			fmt.Printf("\n  [%d] ", i)
			printACE(ace, resolver, guidResolver, "  ")
		}
	}
}

func printDiff(diff *gontsd.DiffResult, resolver resolve.SIDResolver, guidResolver resolve.SchemaGUIDResolver) {
	if diff == nil || !diff.HasChanges() {
		fmt.Println("No changes detected.")
		return
	}

	if diff.OwnerChanged {
		fmt.Println("\nOwner Changed:")
		fmt.Printf("  - Old: %s\n", resolve.FormatSID(diff.OldOwner, resolver))
		fmt.Printf("  + New: %s\n", resolve.FormatSID(diff.NewOwner, resolver))
	}

	if diff.GroupChanged {
		fmt.Println("\nGroup Changed:")
		fmt.Printf("  - Old: %s\n", resolve.FormatSID(diff.OldGroup, resolver))
		fmt.Printf("  + New: %s\n", resolve.FormatSID(diff.NewGroup, resolver))
	}

	if diff.ControlFlagsChanged {
		fmt.Println("\nControl Flags Changed:")
		fmt.Printf("  - Old: %s\n", diff.OldControlFlags)
		fmt.Printf("  + New: %s\n", diff.NewControlFlags)
	}

	if diff.DACLDiff != nil {
		fmt.Println("\nDACL Changes:")
		printACLDiff(diff.DACLDiff, resolver, guidResolver)
	}
}

func printACLDiff(aclDiff *gontsd.ACLDiff, resolver resolve.SIDResolver, guidResolver resolve.SchemaGUIDResolver) {
	if aclDiff.RevisionChanged {
		fmt.Printf("  Revision: %d -> %d\n", aclDiff.OldRevision, aclDiff.NewRevision)
	}

	for _, aceDiff := range aclDiff.ACEDiffs {
		dt := aceDiff.Type

		if dt.Has(gontsd.DiffAdded) {
			fmt.Printf("  [+] Added at position %d:\n", aceDiff.NewPosition)
			printACE(aceDiff.NewACE, resolver, guidResolver, "      ")
		} else if dt.Has(gontsd.DiffRemoved) {
			fmt.Printf("  [-] Removed from position %d:\n", aceDiff.OldPosition)
			printACE(aceDiff.OldACE, resolver, guidResolver, "      ")
		} else if dt.Has(gontsd.DiffModified) && dt.Has(gontsd.DiffReordered) {
			fmt.Printf("  [~↔] Modified and moved from position %d to %d:\n", aceDiff.OldPosition, aceDiff.NewPosition)
			printModifiedACE(aceDiff, resolver, guidResolver, "      ")
		} else if dt.Has(gontsd.DiffModified) {
			fmt.Printf("  [~] Modified at position %d:\n", aceDiff.NewPosition)
			printModifiedACE(aceDiff, resolver, guidResolver, "      ")
		} else if dt.Has(gontsd.DiffReordered) {
			fmt.Printf("  [↔] Moved from position %d to %d:\n", aceDiff.OldPosition, aceDiff.NewPosition)
			printACE(aceDiff.NewACE, resolver, guidResolver, "      ")
		}
	}
}

func printACE(ace gontsd.ACE, resolver resolve.SIDResolver, guidResolver resolve.SchemaGUIDResolver, indent string) {
	if ace == nil {
		fmt.Printf("%s<nil>\n", indent)
		return
	}

	fmt.Printf("%s%sACE:\n", indent, ace.Type())
	fmt.Printf("%s  Trustee: %s\n", indent, resolve.FormatSID(ace.SID(), resolver))
	fmt.Printf("%s  Mask:  %s\n", indent, ace.Mask())
	if objGUID := ace.ObjectTypeGUID(); objGUID != "" {
		fmt.Printf("%s  ObjectType: %s\n", indent, resolve.FormatGUID(objGUID, guidResolver))
	}
	if inhGUID := ace.InheritedObjectTypeGUID(); inhGUID != "" {
		fmt.Printf("%s  InheritedObjectType: %s\n", indent, resolve.FormatGUID(inhGUID, guidResolver))
	}

	if appData := ace.ApplicationData(); len(appData) > 0 {
		fmt.Printf("%s  Condition: %d bytes\n", indent, len(appData))
	}
}


func printModifiedACE(d gontsd.ACEDiff, resolver resolve.SIDResolver, guidResolver resolve.SchemaGUIDResolver, indent string) {
	if d.OldACE == nil || d.NewACE == nil {
		fmt.Printf("%s<nil>\n", indent)
		return
	}

	added, removed, unchanged := d.CompareAccessRights()

	fmt.Printf("%s%sACE:\n", indent, d.NewACE.Type())
	fmt.Printf("%s  Trustee: %s\n", indent, resolve.FormatSID(d.NewACE.SID(), resolver))
	fmt.Printf("%s  Mask: %s -> %s\n", indent, d.OldACE.Mask(), d.NewACE.Mask())

	if objGUID := d.NewACE.ObjectTypeGUID(); objGUID != "" {
		fmt.Printf("%s  ObjectType: %s\n", indent, resolve.FormatGUID(objGUID, guidResolver))
	}
	if inhGUID := d.NewACE.InheritedObjectTypeGUID(); inhGUID != "" {
		fmt.Printf("%s  InheritedObjectType: %s\n", indent, resolve.FormatGUID(inhGUID, guidResolver))
	}

	if len(removed) > 0 {
		fmt.Printf("%s  -Rights: %v\n", indent, removed)
	}
	if len(added) > 0 {
		fmt.Printf("%s  +Rights: %v\n", indent, added)
	}
	if len(unchanged) > 0 {
		fmt.Printf("%s   Rights: %v\n", indent, unchanged)
	}
}

