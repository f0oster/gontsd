package main

import (
	"fmt"
	"os"

	"github.com/f0oster/gontsd"
)

func main() {
	data := []map[string]interface{}{
		{
			"Type":                           "Local File Local Account Permissions",
			"Description":                    "The full output of the Windows Security Descriptor in native binary format for the NTFS ACLs on a specific file that has only local account permissions mapped.",
			"PathToSecurityDescriptorBinary": `.\\sd.bin`,
		},
		{
			"Type":                           "Local File Domain Account Permissions",
			"Description":                    "The full output of the Windows Security Descriptor in native binary format for the NTFS ACLs on a specific file that has domain account permissions mapped.",
			"PathToSecurityDescriptorBinary": `.\\sd-domain.bin`,
		},
		{
			"Type":                           "ActiveDirectory Domain Group Permissions",
			"Description":                    "The full output of the Windows Security Descriptor in native binary format for the ACLs set on a specific Active Directory Group",
			"PathToSecurityDescriptorBinary": `.\\sd-domain-customperm.bin`,
		},
	}

	for _, item := range data {
		fmt.Println("Type:", item["Type"])
		fmt.Println("Description:", item["Description"])
		fmt.Println("Stored in:", item["PathToSecurityDescriptorBinary"])

		descriptor, err := os.ReadFile(item["PathToSecurityDescriptorBinary"].(string))
		if err != nil {
			fmt.Printf("Failed to read file: %v\n", err)
			return
		}

		sdstring, err := gontsd.ParseToString(descriptor)
		if err != nil {
			fmt.Printf("Error parsing SD: %s", err)
			return
		}

		fmt.Printf("%s\n", sdstring)
	}
}
