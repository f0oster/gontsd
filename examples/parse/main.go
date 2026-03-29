// Example: Parsing a Windows NT Security Descriptor
//
// Usage:
//
//	go run ./examples/parse <path-to-binary-sd>
package main

import (
	"fmt"
	"os"

	"github.com/f0oster/gontsd"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <sd-binary-file>\n", os.Args[0])
		os.Exit(1)
	}

	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read file: %v\n", err)
		os.Exit(1)
	}

	sd, err := gontsd.Parse(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Owner: %s\n", sd.OwnerSID.Parsed)
	fmt.Printf("Group: %s\n", sd.GroupSID.Parsed)
	fmt.Printf("Control: %s\n", sd.ControlFlags)

	if sd.DACL != nil {
		fmt.Printf("\nDACL (%d ACEs):\n", len(sd.DACL.ACEs))
		for i, ace := range sd.DACL.ACEs {
			fmt.Printf("  [%d] %s SID=%s Mask=%s\n",
				i, ace.Type(), ace.SID().Parsed, ace.Mask())
			if guid := ace.ObjectTypeGUID(); guid != "" {
				fmt.Printf("       ObjectType: %s\n", guid)
			}
		}
	}

	if sd.SACL != nil {
		fmt.Printf("\nSACL (%d ACEs):\n", len(sd.SACL.ACEs))
		for i, ace := range sd.SACL.ACEs {
			fmt.Printf("  [%d] %s SID=%s Mask=%s\n",
				i, ace.Type(), ace.SID().Parsed, ace.Mask())
		}
	}
}
