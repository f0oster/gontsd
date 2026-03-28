// Example: Comparing two Windows NT Security Descriptors
//
// Usage:
//
//	go run ./examples/compare <old-sd-file> <new-sd-file>
package main

import (
	"fmt"
	"os"

	"github.com/f0oster/gontsd"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "usage: %s <old-sd-file> <new-sd-file>\n", os.Args[0])
		os.Exit(1)
	}

	oldData, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read old file: %v\n", err)
		os.Exit(1)
	}
	newData, err := os.ReadFile(os.Args[2])
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read new file: %v\n", err)
		os.Exit(1)
	}

	oldSD, err := gontsd.Parse(oldData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse old SD: %v\n", err)
		os.Exit(1)
	}
	newSD, err := gontsd.Parse(newData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse new SD: %v\n", err)
		os.Exit(1)
	}

	diff := gontsd.Compare(oldSD, newSD)

	if !diff.HasChanges() {
		fmt.Println("No changes.")
		return
	}

	if diff.OwnerChanged {
		fmt.Printf("Owner: %s -> %s\n", diff.OldOwner.Parsed, diff.NewOwner.Parsed)
	}
	if diff.GroupChanged {
		fmt.Printf("Group: %s -> %s\n", diff.OldGroup.Parsed, diff.NewGroup.Parsed)
	}
	if diff.ControlFlagsChanged {
		fmt.Printf("Control: 0x%04X -> 0x%04X\n", diff.OldControlFlags, diff.NewControlFlags)
	}

	printACLDiff("DACL", diff.DACLDiff)
	printACLDiff("SACL", diff.SACLDiff)
}

func printACLDiff(name string, aclDiff *gontsd.ACLDiff) {
	if aclDiff == nil {
		return
	}

	fmt.Printf("\n%s Changes:\n", name)
	for _, d := range aclDiff.ACEDiffs {
		dt := d.Type
		switch {
		case dt.Has(gontsd.DiffAdded):
			fmt.Printf("  [+] pos %d: %s SID=%s\n",
				d.NewPosition, d.NewACE.Type(), d.NewACE.GetSID().Parsed)
		case dt.Has(gontsd.DiffRemoved):
			fmt.Printf("  [-] pos %d: %s SID=%s\n",
				d.OldPosition, d.OldACE.Type(), d.OldACE.GetSID().Parsed)
		case dt.Has(gontsd.DiffModified) && dt.Has(gontsd.DiffReordered):
			fmt.Printf("  [~↔] pos %d->%d: %s SID=%s mask 0x%X->0x%X\n",
				d.OldPosition, d.NewPosition, d.NewACE.Type(),
				d.NewACE.GetSID().Parsed, d.OldACE.GetMask(), d.NewACE.GetMask())
		case dt.Has(gontsd.DiffModified):
			fmt.Printf("  [~] pos %d: %s SID=%s mask 0x%X->0x%X\n",
				d.NewPosition, d.NewACE.Type(),
				d.NewACE.GetSID().Parsed, d.OldACE.GetMask(), d.NewACE.GetMask())
		case dt.Has(gontsd.DiffReordered):
			fmt.Printf("  [↔] pos %d->%d: %s SID=%s\n",
				d.OldPosition, d.NewPosition, d.NewACE.Type(), d.NewACE.GetSID().Parsed)
		}
	}
}
