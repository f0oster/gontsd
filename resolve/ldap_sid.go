package resolve

import (
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/f0oster/gontsd"
	"github.com/go-ldap/ldap/v3"
)

// LDAPConfig holds LDAP connection settings.
type LDAPConfig struct {
	Server   string // e.g., "ldap://dc.example.com:389" or "ldaps://dc.example.com:636"
	BaseDN   string // e.g., "DC=example,DC=com"
	BindDN   string // e.g., "CN=admin,DC=example,DC=com"
	Password string
	UseTLS   bool // Use STARTTLS for ldap:// connections
}

// LDAPSIDResolver resolves SIDs by querying Active Directory.
type LDAPSIDResolver struct {
	client *LDAPClient
	cache  map[string]string // SID string -> resolved name
	mu     sync.RWMutex
}

var _ SIDResolver = (*LDAPSIDResolver)(nil)

// NewLDAPSIDResolver creates a new LDAP-backed SID resolver.
func NewLDAPSIDResolver(client *LDAPClient) *LDAPSIDResolver {
	return &LDAPSIDResolver{
		client: client,
		cache:  make(map[string]string),
	}
}

func (r *LDAPSIDResolver) Resolve(sid *gontsd.SID) (string, error) {
	if sid == nil {
		return "", fmt.Errorf("nil SID")
	}

	if name, ok := WellKnownSIDs[sid.Parsed]; ok {
		return name, nil
	}

	r.mu.RLock()
	if name, ok := r.cache[sid.Parsed]; ok {
		r.mu.RUnlock()
		return name, nil
	}
	r.mu.RUnlock()

	name, err := r.queryAD(sid)
	if err != nil {
		return "", err
	}

	r.mu.Lock()
	r.cache[sid.Parsed] = name
	r.mu.Unlock()

	return name, nil
}

func (r *LDAPSIDResolver) ResolveBatch(sids []*gontsd.SID) (map[string]string, error) {
	results := make(map[string]string)

	for _, sid := range sids {
		if sid == nil {
			continue
		}
		name, err := r.Resolve(sid)
		if err != nil {
			results[sid.Parsed] = fmt.Sprintf("<error: %v>", err)
		} else {
			results[sid.Parsed] = name
		}
	}

	return results, nil
}

func (r *LDAPSIDResolver) queryAD(sid *gontsd.SID) (string, error) {
	binarySID := sidToBinaryString(sid.Raw)

	searchRequest := ldap.NewSearchRequest(
		r.client.BaseDN(),
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		fmt.Sprintf("(objectSid=%s)", binarySID),
		[]string{"sAMAccountName", "distinguishedName", "name"},
		nil,
	)

	sr, err := r.client.Conn().Search(searchRequest)
	if err != nil {
		return "", fmt.Errorf("LDAP search failed: %w", err)
	}

	if len(sr.Entries) == 0 {
		return "", fmt.Errorf("SID not found in AD: %s", sid.Parsed)
	}

	entry := sr.Entries[0]
	samName := entry.GetAttributeValue("sAMAccountName")
	dn := entry.GetAttributeValue("distinguishedName")

	if samName != "" && dn != "" {
		return fmt.Sprintf("%s (%s)", samName, dn), nil
	}
	if samName != "" {
		return samName, nil
	}
	if dn != "" {
		return dn, nil
	}
	if name := entry.GetAttributeValue("name"); name != "" {
		return name, nil
	}
	return "", fmt.Errorf("no name attributes found for SID: %s", sid.Parsed)
}

// sidToBinaryString converts a raw SID to LDAP binary escape format (\XX per byte)
func sidToBinaryString(raw []byte) string {
	result := ""
	for _, b := range raw {
		result += fmt.Sprintf("\\%02x", b)
	}
	return result
}

// SIDFromString parses a SID string (e.g., "S-1-5-21-...") into binary format.
func SIDFromString(sidStr string) ([]byte, error) {
	var revision uint8
	var identifierAuthority uint64
	var subAuthorities []uint32

	var subAuthStr string
	n, err := fmt.Sscanf(sidStr, "S-%d-%d-%s", &revision, &identifierAuthority, &subAuthStr)
	if err != nil && n < 2 {
		return nil, fmt.Errorf("invalid SID format: %s", sidStr)
	}

	if n >= 3 && subAuthStr != "" {
		remaining := sidStr
		for i := 0; i < 3; i++ {
			for j := 0; j < len(remaining); j++ {
				if remaining[j] == '-' {
					remaining = remaining[j+1:]
					break
				}
			}
		}

		for remaining != "" {
			var subAuth uint32
			var consumed int
			for consumed = 0; consumed < len(remaining); consumed++ {
				if remaining[consumed] == '-' {
					break
				}
			}
			_, err := fmt.Sscanf(remaining[:consumed], "%d", &subAuth)
			if err != nil {
				break
			}
			subAuthorities = append(subAuthorities, subAuth)
			if consumed >= len(remaining) || remaining[consumed] != '-' {
				break
			}
			remaining = remaining[consumed+1:]
		}
	}

	// Build binary SID
	// SID structure: Revision (1) + SubAuthorityCount (1) + IdentifierAuthority (6) + SubAuthorities (4 * count)
	sidLen := 8 + len(subAuthorities)*4
	raw := make([]byte, sidLen)

	raw[0] = revision
	raw[1] = uint8(len(subAuthorities))

	// Identifier authority is 6 bytes big-endian
	for i := 0; i < 6; i++ {
		raw[7-i] = uint8(identifierAuthority >> (8 * i))
	}

	// Sub-authorities are 4 bytes each, little-endian
	for i, subAuth := range subAuthorities {
		binary.LittleEndian.PutUint32(raw[8+i*4:], subAuth)
	}

	return raw, nil
}
