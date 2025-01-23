package gontsd

import (
	"fmt"
	"strings"

	"github.com/f0oster/gontsd/internal/sd"
)

type SecurityDescriptor struct {
	OwnerSID *SID
	GroupSID *SID
	DACL     *ACL
	SACL     *ACL
}

type SID struct {
	Parsed       string
	ResolvedName string
}

type ACE interface {
	Type() uint8
	String() string
}

type ACL struct {
	ACEs []ACE
}

func (acl *ACL) String() string {
	if acl == nil {
		return "<nil>"
	}
	var sb strings.Builder
	for i, ace := range acl.ACEs {
		sb.WriteString(fmt.Sprintf("  ACE[%d]:\n%s\n", i, ace.String()))
	}
	return sb.String()
}

func Parse(data []byte) (*SecurityDescriptor, error) {
	internalSD, err := sd.ParseSecurityDescriptor(data)
	if err != nil {
		return nil, err
	}

	pub := &SecurityDescriptor{}

	if internalSD.OwnerSID != nil {
		pub.OwnerSID = &SID{
			Parsed:       internalSD.OwnerSID.Parsed,
			ResolvedName: internalSD.OwnerSID.ResolvedName,
		}
	}
	if internalSD.GroupSID != nil {
		pub.GroupSID = &SID{
			Parsed:       internalSD.GroupSID.Parsed,
			ResolvedName: internalSD.GroupSID.ResolvedName,
		}
	}
	if internalSD.DACL != nil {
		dacl := &ACL{}
		for _, internalACE := range internalSD.DACL.AccessControlEntries {
			dacl.ACEs = append(dacl.ACEs, internalACE)
		}
		pub.DACL = dacl
	}

	return pub, nil
}

func ParseToString(data []byte) (string, error) {
	internalSD, err := sd.ParseSecurityDescriptor(data)
	if err != nil {
		return "", err
	}

	return internalSD.String(), nil
}
