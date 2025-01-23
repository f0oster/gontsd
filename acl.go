package gontsd

import (
	"fmt"
	"strings"
)

type ACL struct {
	Revision uint8
	Sbz1     uint8
	Size     uint16
	Count    uint16
	Sbz2     uint16
	ACEs     []ACE
}

func (acl *ACL) String() string {
	if acl == nil {
		return "<nil>"
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("ACL (Revision: %d, ACE count: %d)\n", acl.Revision, acl.Count))
	for i, ace := range acl.ACEs {
		sb.WriteString(fmt.Sprintf("  ACE[%d]:\n%s\n", i, indent(ace.String(), "    ")))
	}
	return sb.String()
}
