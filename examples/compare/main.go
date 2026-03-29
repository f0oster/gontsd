// Example: Compare two versions of a security descriptor and display
// the differences, resolving SIDs and GUIDs via LDAP.
//
// Usage:
//
//	go run ./examples/compare -ldap-server "ldaps://dc.example.com:636" ...
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/f0oster/gontsd"
	"github.com/f0oster/gontsd/ldapresolver"
)

func main() {
	ldapServer := flag.String("ldap-server", "", "LDAP server URL (e.g., ldap://dc.example.com:389)")
	ldapBaseDN := flag.String("ldap-basedn", "", "LDAP base DN (e.g., DC=example,DC=com)")
	ldapBindDN := flag.String("ldap-binddn", "", "LDAP bind DN")
	ldapPassword := flag.String("ldap-password", "", "LDAP password")
	ldapTLS := flag.Bool("ldap-tls", false, "Use STARTTLS")
	ldapInsecure := flag.Bool("ldap-insecure", false, "Skip TLS certificate verification")
	flag.Parse()

	if *ldapServer == "" || *ldapBaseDN == "" {
		fmt.Fprintf(os.Stderr, "usage: %s -ldap-server <url> -ldap-basedn <dn> [-ldap-binddn <dn> -ldap-password <pw>]\n", os.Args[0])
		os.Exit(1)
	}

	client, err := ldapresolver.NewLDAPClient(ldapresolver.LDAPConfig{
		Server:             *ldapServer,
		BaseDN:             *ldapBaseDN,
		BindDN:             *ldapBindDN,
		Password:           *ldapPassword,
		UseTLS:             *ldapTLS,
		InsecureSkipVerify: *ldapInsecure,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "LDAP connection failed: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

	r, err := ldapresolver.NewLDAPResolver(client)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to set up resolver: %v\n", err)
		os.Exit(1)
	}

	runComparisons(&r.Resolver)
}

func runComparisons(r *gontsd.Resolver) {
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

		oldSD, err := gontsd.Parse(oldData, r)
		if err != nil {
			fmt.Printf("Failed to parse old SD: %v\n", err)
			continue
		}

		newSD, err := gontsd.Parse(newData, r)
		if err != nil {
			fmt.Printf("Failed to parse new SD: %v\n", err)
			continue
		}

		diff := gontsd.Compare(oldSD, newSD)
		printDiff(diff)
	}
}

func printDiff(diff *gontsd.DiffResult) {
	if diff == nil || !diff.HasChanges() {
		fmt.Println("No changes detected.")
		return
	}

	if diff.OwnerChanged {
		fmt.Println("\nOwner Changed:")
		fmt.Printf("  - Old: %s\n", diff.OldOwner.Resolved())
		fmt.Printf("  + New: %s\n", diff.NewOwner.Resolved())
	}

	if diff.GroupChanged {
		fmt.Println("\nGroup Changed:")
		fmt.Printf("  - Old: %s\n", diff.OldGroup.Resolved())
		fmt.Printf("  + New: %s\n", diff.NewGroup.Resolved())
	}

	if diff.ControlFlagsChanged {
		fmt.Println("\nControl Flags Changed:")
		fmt.Printf("  - Old: %s\n", diff.OldControlFlags)
		fmt.Printf("  + New: %s\n", diff.NewControlFlags)
	}

	if diff.DACLDiff != nil {
		fmt.Println("\nDACL Changes:")
		printACLDiff(diff.DACLDiff)
	}
}

func printACLDiff(aclDiff *gontsd.ACLDiff) {
	if aclDiff.RevisionChanged {
		fmt.Printf("  Revision: %d -> %d\n", aclDiff.OldRevision, aclDiff.NewRevision)
	}

	for _, aceDiff := range aclDiff.ACEDiffs {
		dt := aceDiff.Type

		if dt.Has(gontsd.DiffAdded) {
			fmt.Printf("  [+] Added at position %d:\n", aceDiff.NewPosition)
			printACE(aceDiff.NewACE, "      ")
		} else if dt.Has(gontsd.DiffRemoved) {
			fmt.Printf("  [-] Removed from position %d:\n", aceDiff.OldPosition)
			printACE(aceDiff.OldACE, "      ")
		} else if dt.Has(gontsd.DiffModified) && dt.Has(gontsd.DiffReordered) {
			fmt.Printf("  [~↔] Modified and moved from position %d to %d:\n", aceDiff.OldPosition, aceDiff.NewPosition)
			printModifiedACE(aceDiff, "      ")
		} else if dt.Has(gontsd.DiffModified) {
			fmt.Printf("  [~] Modified at position %d:\n", aceDiff.NewPosition)
			printModifiedACE(aceDiff, "      ")
		} else if dt.Has(gontsd.DiffReordered) {
			fmt.Printf("  [↔] Moved from position %d to %d:\n", aceDiff.OldPosition, aceDiff.NewPosition)
			printACE(aceDiff.NewACE, "      ")
		}
	}
}

func printACE(ace gontsd.ACE, indent string) {
	if ace == nil {
		fmt.Printf("%s<nil>\n", indent)
		return
	}

	fmt.Printf("%s%sACE:\n", indent, ace.Type())
	fmt.Printf("%s  Trustee: %s\n", indent, ace.SID().Resolved())
	fmt.Printf("%s  Mask:    %s\n", indent, ace.Mask())
	if objGUID := ace.ObjectTypeGUID(); objGUID != nil {
		fmt.Printf("%s  ObjectType: %s\n", indent, objGUID.Resolved())
	}
	if inhGUID := ace.InheritedObjectTypeGUID(); inhGUID != nil {
		fmt.Printf("%s  InheritedObjectType: %s\n", indent, inhGUID.Resolved())
	}
	if appData := ace.ApplicationData(); len(appData) > 0 {
		fmt.Printf("%s  Condition: %d bytes\n", indent, len(appData))
	}
}

func printModifiedACE(d gontsd.ACEDiff, indent string) {
	if d.OldACE == nil || d.NewACE == nil {
		fmt.Printf("%s<nil>\n", indent)
		return
	}

	added, removed, unchanged := d.CompareAccessRights()

	fmt.Printf("%s%sACE:\n", indent, d.NewACE.Type())
	fmt.Printf("%s  Trustee: %s\n", indent, d.NewACE.SID().Resolved())
	fmt.Printf("%s  Mask:    %s -> %s\n", indent, d.OldACE.Mask(), d.NewACE.Mask())

	if objGUID := d.NewACE.ObjectTypeGUID(); objGUID != nil {
		fmt.Printf("%s  ObjectType: %s\n", indent, objGUID.Resolved())
	}
	if inhGUID := d.NewACE.InheritedObjectTypeGUID(); inhGUID != nil {
		fmt.Printf("%s  InheritedObjectType: %s\n", indent, inhGUID.Resolved())
	}

	if len(removed) > 0 {
		fmt.Printf("%s  - %v\n", indent, removed)
	}
	if len(added) > 0 {
		fmt.Printf("%s  + %v\n", indent, added)
	}
	if len(unchanged) > 0 {
		fmt.Printf("%s    %v\n", indent, unchanged)
	}
}

