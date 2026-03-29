package gontsd

import (
	"fmt"
	"strings"
)

// ACL represents an Access Control List containing ACE entries.
type ACL struct {
	Revision uint8
	sbz1     uint8
	size     uint16
	count    uint16
	sbz2     uint16
	ACEs     []ACE
}

func (acl *ACL) String() string {
	if acl == nil {
		return "<nil>"
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("ACL (Revision: %d, ACE count: %d)\n", acl.Revision, len(acl.ACEs)))
	for i, ace := range acl.ACEs {
		sb.WriteString(fmt.Sprintf("  ACE[%d]:\n%s\n", i, indent(ace.String(), "    ")))
	}
	return sb.String()
}
