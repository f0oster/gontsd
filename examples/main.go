// Example: Parsing and Comparing NT Security Descriptors
//
// This example demonstrates:
//   - Parsing binary ntSecurityDescriptor data
//   - Comparing two security descriptors to detect changes
//   - Resolving SIDs to human-readable names (well-known and LDAP)
//   - Resolving schema GUIDs to extended right/property names
//
// Run without LDAP (uses well-known SIDs only):
//
//	go run ./examples
//
// Run with LDAP resolution:
//
//	go run ./examples \
//	  -ldap-server "ldap://dc.example.com:389" \
//	  -ldap-basedn "DC=example,DC=com" \
//	  -ldap-binddn "CN=user,DC=example,DC=com" \
//	  -ldap-password "password"
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/f0oster/gontsd"
	"github.com/f0oster/gontsd/resolve"
)

func main() {
	ldapServer := flag.String("ldap-server", "", "LDAP server URL (e.g., ldap://dc.example.com:389)")
	ldapBaseDN := flag.String("ldap-basedn", "", "LDAP base DN (e.g., DC=example,DC=com)")
	ldapBindDN := flag.String("ldap-binddn", "", "LDAP bind DN")
	ldapPassword := flag.String("ldap-password", "", "LDAP password")
	ldapTLS := flag.Bool("ldap-tls", false, "Use STARTTLS")
	flag.Parse()

	var resolver resolve.SIDResolver = resolve.WellKnownSIDResolver{}
	var guidResolver resolve.SchemaGUIDResolver = resolve.WellKnownSchemaGUIDResolver{}

	if *ldapServer != "" {
		client, err := resolve.NewLDAPClient(resolve.LDAPConfig{
			Server:   *ldapServer,
			BaseDN:   *ldapBaseDN,
			BindDN:   *ldapBindDN,
			Password: *ldapPassword,
			UseTLS:   *ldapTLS,
		})
		if err != nil {
			fmt.Printf("Warning: Failed to connect to LDAP: %v\n", err)
		} else {
			defer client.Close()
			sidResolver := resolve.NewLDAPSIDResolver(client)
			resolver = resolve.ChainSIDResolver{
				Resolvers: []resolve.SIDResolver{
					resolve.WellKnownSIDResolver{},
					sidResolver,
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
				fmt.Printf("LDAP GUID resolver configured (cached %d extended rights)\n", ldapGUIDResolver.CacheSize())
			}
		}
	}

	runTestCaseComparisons(resolver, guidResolver)
	dumpSecurityDescriptor("./test_cases/root_domain/sd-domainroot.bin", resolver, guidResolver)
}

func runTestCaseComparisons(resolver resolve.SIDResolver, guidResolver resolve.SchemaGUIDResolver) {
	fmt.Println()
	fmt.Println("=== Test Case Comparisons ===")

	testCases := []struct {
		Name        string
		DefaultPath string
		ChangePath  string
	}{
		{
			Name:        "Added Principal To ACE",
			DefaultPath: "./test_cases/adding_new_user/sd-filedomain_default.bin",
			ChangePath:  "./test_cases/adding_new_user/sd-filedomain_change.bin",
		},
		{
			Name:        "Removed Flag From ACE",
			DefaultPath: "./test_cases/removing_flag/sd-filedomain_default.bin",
			ChangePath:  "./test_cases/removing_flag/sd-filedomain_change.bin",
		},
		{
			Name:        "Added Flag To ACE",
			DefaultPath: "./test_cases/adding_flag/sd-filedomain_default.bin",
			ChangePath:  "./test_cases/adding_flag/sd-filedomain_change.bin",
		},
	}

	for _, tc := range testCases {
		fmt.Printf("\n=== Test Case: %s ===\n", tc.Name)

		defaultData, err := os.ReadFile(tc.DefaultPath)
		if err != nil {
			fmt.Printf("Failed to read default file: %v\n", err)
			continue
		}

		changeData, err := os.ReadFile(tc.ChangePath)
		if err != nil {
			fmt.Printf("Failed to read change file: %v\n", err)
			continue
		}

		defaultSD, err := gontsd.Parse(defaultData)
		if err != nil {
			fmt.Printf("Failed to parse default SD: %v\n", err)
			continue
		}

		changeSD, err := gontsd.Parse(changeData)
		if err != nil {
			fmt.Printf("Failed to parse change SD: %v\n", err)
			continue
		}

		diff := gontsd.Compare(defaultSD, changeSD)
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

	fmt.Printf("\nOwner: %s\n", resolveSID(sd.OwnerSID, resolver))
	fmt.Printf("Group: %s\n", resolveSID(sd.GroupSID, resolver))
	fmt.Printf("Control: 0x%04X\n", sd.ControlFlags)

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
		fmt.Printf("  - Old: %s\n", resolveSID(diff.OldOwner, resolver))
		fmt.Printf("  + New: %s\n", resolveSID(diff.NewOwner, resolver))
	}

	if diff.GroupChanged {
		fmt.Println("\nGroup Changed:")
		fmt.Printf("  - Old: %s\n", resolveSID(diff.OldGroup, resolver))
		fmt.Printf("  + New: %s\n", resolveSID(diff.NewGroup, resolver))
	}

	if diff.ControlFlagsChanged {
		fmt.Println("\nControl Flags Changed:")
		fmt.Printf("  - Old: 0x%04X\n", diff.OldControlFlags)
		fmt.Printf("  + New: 0x%04X\n", diff.NewControlFlags)
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
		switch aceDiff.Type {
		case gontsd.DiffAdded:
			fmt.Printf("  [+] Added at position %d:\n", aceDiff.Position)
			printACE(aceDiff.NewACE, resolver, guidResolver, "      ")
		case gontsd.DiffRemoved:
			fmt.Printf("  [-] Removed from position %d:\n", aceDiff.Position)
			printACE(aceDiff.OldACE, resolver, guidResolver, "      ")
		case gontsd.DiffModified:
			fmt.Printf("  [~] Modified at position %d:\n", aceDiff.Position)
			printModifiedACE(aceDiff.OldACE, aceDiff.NewACE, resolver, guidResolver, "      ")
		case gontsd.DiffReordered:
			fmt.Printf("  [↔] Reordered to position %d:\n", aceDiff.Position)
			printACE(aceDiff.NewACE, resolver, guidResolver, "      ")
		}
	}
}

func printACE(ace gontsd.ACE, resolver resolve.SIDResolver, guidResolver resolve.SchemaGUIDResolver, indent string) {
	if ace == nil {
		fmt.Printf("%s<nil>\n", indent)
		return
	}

	fmt.Printf("%s%s:\n", indent, getACETypeName(ace))
	fmt.Printf("%s  SID:   %s\n", indent, resolveSID(ace.GetSID(), resolver))
	fmt.Printf("%s  Mask:  0x%08X\n", indent, ace.GetMask())
	fmt.Printf("%s  Flags: %v\n", indent, ace.GetFlags())
	if objGUID := ace.GetObjectTypeGUID(); objGUID != "" {
		fmt.Printf("%s  ObjectType: %s\n", indent, resolveGUIDWithDetails(objGUID, guidResolver, indent+"            "))
	}

	if inhGUID := ace.GetInheritedObjectTypeGUID(); inhGUID != "" {
		fmt.Printf("%s  InheritedObjectType: %s\n", indent, resolveGUID(inhGUID, guidResolver))
	}

	switch a := ace.(type) {
	case *gontsd.AccessAllowedCallbackACE:
		fmt.Printf("%s  Condition: %d bytes\n", indent, len(a.ApplicationData))
	case *gontsd.AccessDeniedCallbackACE:
		fmt.Printf("%s  Condition: %d bytes\n", indent, len(a.ApplicationData))
	case *gontsd.AccessAllowedCallbackObjectACE:
		fmt.Printf("%s  Condition: %d bytes\n", indent, len(a.ApplicationData))
	case *gontsd.AccessDeniedCallbackObjectACE:
		fmt.Printf("%s  Condition: %d bytes\n", indent, len(a.ApplicationData))
	}
}

func resolveSID(sid *gontsd.SID, resolver resolve.SIDResolver) string {
	if sid == nil {
		return "<nil>"
	}

	name, err := resolver.Resolve(sid)
	if err != nil {
		return fmt.Sprintf("%s (unresolved)", sid.Parsed)
	}
	return fmt.Sprintf("%s (%s)", sid.Parsed, name)
}

func resolveGUID(guid string, resolver resolve.SchemaGUIDResolver) string {
	if guid == "" {
		return ""
	}
	if resolver == nil {
		return guid
	}
	info, err := resolver.ResolveGUID(guid)
	if err != nil {
		return guid
	}
	return fmt.Sprintf("%s (%s) [%s]", info.Name, guid, info.Type)
}

func resolveGUIDWithDetails(guid string, resolver resolve.SchemaGUIDResolver, indent string) string {
	if guid == "" {
		return ""
	}
	if resolver == nil {
		return guid
	}
	info, err := resolver.ResolveGUID(guid)
	if err != nil {
		return guid
	}

	var result strings.Builder
	result.WriteString(fmt.Sprintf("%s (%s) [%s]", info.Name, guid, info.Type))

	if info.Description != "" {
		result.WriteString(fmt.Sprintf("\n%s  Description: %s", indent, info.Description))
	}
	if len(info.AppliesTo) > 0 {
		result.WriteString(fmt.Sprintf("\n%s  Applies to: %s", indent, strings.Join(info.AppliesTo, ", ")))
	}

	return result.String()
}

func printModifiedACE(oldACE, newACE gontsd.ACE, resolver resolve.SIDResolver, guidResolver resolve.SchemaGUIDResolver, indent string) {
	if oldACE == nil || newACE == nil {
		fmt.Printf("%s<nil>\n", indent)
		return
	}

	added, removed, unchanged := compareFlagSlices(oldACE.GetFlags(), newACE.GetFlags())

	fmt.Printf("%s%s:\n", indent, getACETypeName(newACE))
	fmt.Printf("%s  SID:  %s\n", indent, resolveSID(newACE.GetSID(), resolver))
	fmt.Printf("%s  Mask: 0x%08X -> 0x%08X\n", indent, oldACE.GetMask(), newACE.GetMask())

	if objGUID := newACE.GetObjectTypeGUID(); objGUID != "" {
		fmt.Printf("%s  ObjectType: %s\n", indent, resolveGUIDWithDetails(objGUID, guidResolver, indent+"            "))
	}

	if inhGUID := newACE.GetInheritedObjectTypeGUID(); inhGUID != "" {
		fmt.Printf("%s  InheritedObjectType: %s\n", indent, resolveGUID(inhGUID, guidResolver))
	}

	if len(removed) > 0 {
		fmt.Printf("%s  RemovedFlags:   %v\n", indent, removed)
	}
	if len(added) > 0 {
		fmt.Printf("%s  AddedFlags:     %v\n", indent, added)
	}
	if len(unchanged) > 0 {
		fmt.Printf("%s  UnchangedFlags: %v\n", indent, unchanged)
	}
}

func compareFlagSlices(oldFlags, newFlags []string) (added, removed, unchanged []string) {
	oldSet := make(map[string]bool)
	newSet := make(map[string]bool)

	for _, f := range oldFlags {
		oldSet[f] = true
	}
	for _, f := range newFlags {
		newSet[f] = true
	}

	for _, f := range oldFlags {
		if !newSet[f] {
			removed = append(removed, f)
		}
	}

	for _, f := range newFlags {
		if !oldSet[f] {
			added = append(added, f)
		}
	}

	for _, f := range oldFlags {
		if newSet[f] {
			unchanged = append(unchanged, f)
		}
	}

	return added, removed, unchanged
}

func getACETypeName(ace gontsd.ACE) string {
	switch ace.(type) {
	case *gontsd.AccessAllowedACE:
		return "AccessAllowedACE"
	case *gontsd.AccessDeniedACE:
		return "AccessDeniedACE"
	case *gontsd.AccessAllowedObjectACE:
		return "AccessAllowedObjectACE"
	case *gontsd.AccessDeniedObjectACE:
		return "AccessDeniedObjectACE"
	case *gontsd.AccessAllowedCallbackACE:
		return "AccessAllowedCallbackACE"
	case *gontsd.AccessDeniedCallbackACE:
		return "AccessDeniedCallbackACE"
	case *gontsd.AccessAllowedCallbackObjectACE:
		return "AccessAllowedCallbackObjectACE"
	case *gontsd.AccessDeniedCallbackObjectACE:
		return "AccessDeniedCallbackObjectACE"
	default:
		return "UnknownACE"
	}
}
