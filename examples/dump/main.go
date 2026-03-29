// Example: Fetch and display a security descriptor from Active Directory.
//
// Usage:
//
//	go run ./examples/dump \
//	  -ldap-server "ldaps://dc.example.com:636" \
//	  -ldap-basedn "DC=example,DC=com" \
//	  -ldap-binddn "user@example.com" \
//	  -ldap-password "password" \
//	  -object-dn "CN=Users,DC=example,DC=com"
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/f0oster/gontsd"
	"github.com/f0oster/gontsd/resolve"
	"github.com/go-ldap/ldap/v3"
)

func main() {
	ldapServer := flag.String("ldap-server", "", "LDAP server URL (e.g., ldap://dc.example.com:389)")
	ldapBaseDN := flag.String("ldap-basedn", "", "LDAP base DN (e.g., DC=example,DC=com)")
	ldapBindDN := flag.String("ldap-binddn", "", "LDAP bind DN")
	ldapPassword := flag.String("ldap-password", "", "LDAP password")
	ldapTLS := flag.Bool("ldap-tls", false, "Use STARTTLS")
	ldapInsecure := flag.Bool("ldap-insecure", false, "Skip TLS certificate verification")
	objectDN := flag.String("object-dn", "", "DN of the object to inspect (required)")
	flag.Parse()

	if *ldapServer == "" || *ldapBaseDN == "" || *objectDN == "" {
		fmt.Fprintf(os.Stderr, "usage: %s -ldap-server <url> -ldap-basedn <dn> -object-dn <dn> [...]\n", os.Args[0])
		os.Exit(1)
	}

	targetDN := *objectDN

	client, err := resolve.NewLDAPClient(resolve.LDAPConfig{
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

	sdBytes, err := fetchSecurityDescriptor(client, targetDN)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	sd, err := gontsd.Parse(sdBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse security descriptor: %v\n", err)
		os.Exit(1)
	}

	r, err := resolve.NewLDAPResolver(client)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to set up resolver: %v\n", err)
		os.Exit(1)
	}

	resolve.ResolveBatchSIDs(r.SIDs, sd.CollectSIDs())

	fmt.Printf("Object:  %s\n", targetDN)
	fmt.Printf("Owner:   %s\n", resolve.FormatSID(sd.OwnerSID, r.SIDs))
	fmt.Printf("Group:   %s\n", resolve.FormatSID(sd.GroupSID, r.SIDs))
	fmt.Printf("Control: %s\n", sd.ControlFlags)

	printACL("DACL", sd.DACL, r)
	printACL("SACL", sd.SACL, r)
}

func fetchSecurityDescriptor(client *resolve.LDAPClient, dn string) ([]byte, error) {
	sdFlagsControl := ldap.NewControlMicrosoftSDFlags()
	sdFlagsControl.ControlValue = 0x07 // owner + group + DACL

	req := ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1, 0, false,
		"(objectClass=*)",
		[]string{},
		[]ldap.Control{sdFlagsControl},
	)

	sr, err := client.Conn().Search(req)
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %w", err)
	}
	if len(sr.Entries) == 0 {
		return nil, fmt.Errorf("object not found: %s", dn)
	}

	sdBytes := sr.Entries[0].GetRawAttributeValue("nTSecurityDescriptor")
	if len(sdBytes) == 0 {
		return nil, fmt.Errorf("nTSecurityDescriptor is empty on %s", dn)
	}
	return sdBytes, nil
}

func printACL(name string, acl *gontsd.ACL, r *resolve.LDAPResolver) {
	if acl == nil {
		return
	}
	fmt.Printf("\n%s (%d ACEs):\n", name, len(acl.ACEs))
	for i, ace := range acl.ACEs {
		fmt.Printf("\n  [%d] %sACE\n", i, ace.Type())
		fmt.Printf("      Trustee: %s\n", resolve.FormatSID(ace.SID(), r.SIDs))
		fmt.Printf("      Mask:    %s\n", ace.Mask())
		if guid := ace.ObjectTypeGUID(); guid != "" {
			fmt.Printf("      ObjectType: %s\n", resolve.FormatGUID(guid, r.GUIDs))
		}
		if guid := ace.InheritedObjectTypeGUID(); guid != "" {
			fmt.Printf("      InheritedObjectType: %s\n", resolve.FormatGUID(guid, r.GUIDs))
		}
		if appData := ace.ApplicationData(); len(appData) > 0 {
			fmt.Printf("      Condition: %d bytes\n", len(appData))
		}
	}
}
