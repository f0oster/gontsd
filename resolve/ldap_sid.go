package resolve

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/f0oster/gontsd"
	"github.com/go-ldap/ldap/v3"
)

// LDAPConfig holds LDAP connection settings.
type LDAPConfig struct {
	Server             string // e.g., "ldap://dc.example.com:389" or "ldaps://dc.example.com:636"
	BaseDN             string // e.g., "DC=example,DC=com"
	BindDN             string // e.g., "CN=admin,DC=example,DC=com"
	Password           string
	UseTLS             bool // Use STARTTLS for ldap:// connections
	InsecureSkipVerify bool // Skip TLS certificate verification
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
	var sb strings.Builder
	for _, b := range raw {
		fmt.Fprintf(&sb, "\\%02x", b)
	}
	return sb.String()
}

// SIDFromString parses a SID string (e.g., "S-1-5-21-...") into binary format.
func SIDFromString(sidStr string) ([]byte, error) {
	if !strings.HasPrefix(sidStr, "S-") {
		return nil, fmt.Errorf("invalid SID format: %s", sidStr)
	}

	parts := strings.Split(sidStr[2:], "-")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid SID format: %s", sidStr)
	}

	revision, err := strconv.ParseUint(parts[0], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("invalid SID revision: %w", err)
	}

	identifierAuthority, err := strconv.ParseUint(parts[1], 10, 48)
	if err != nil {
		return nil, fmt.Errorf("invalid SID identifier authority: %w", err)
	}

	var subAuthorities []uint32
	for _, part := range parts[2:] {
		sa, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid SID sub-authority %q: %w", part, err)
		}
		subAuthorities = append(subAuthorities, uint32(sa))
	}

	// SID structure: Revision (1) + SubAuthorityCount (1) + IdentifierAuthority (6) + SubAuthorities (4 * count)
	raw := make([]byte, 8+len(subAuthorities)*4)

	raw[0] = uint8(revision)
	raw[1] = uint8(len(subAuthorities))

	// Identifier authority is 6 bytes big-endian
	for i := range 6 {
		raw[7-i] = uint8(identifierAuthority >> (8 * i))
	}

	// Sub-authorities are 4 bytes each, little-endian
	for i, subAuth := range subAuthorities {
		binary.LittleEndian.PutUint32(raw[8+i*4:], subAuth)
	}

	return raw, nil
}
