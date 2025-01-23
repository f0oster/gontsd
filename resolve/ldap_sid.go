package resolve

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/f0oster/gontsd"
	"github.com/go-ldap/ldap/v3"
)

// LDAPConfig holds LDAP connection settings
type LDAPConfig struct {
	Server   string // e.g., "ldap://dc.example.com:389" or "ldaps://dc.example.com:636"
	BaseDN   string // e.g., "DC=example,DC=com"
	BindDN   string // e.g., "CN=admin,DC=example,DC=com"
	Password string
	UseTLS   bool // Use STARTTLS for ldap:// connections
}

// LDAPSIDResolver resolves SIDs via LDAP queries to Active Directory
type LDAPSIDResolver struct {
	config LDAPConfig
	conn   *ldap.Conn
	cache  map[string]string // SID string -> resolved name
	mu     sync.RWMutex
}

var _ SIDResolver = (*LDAPSIDResolver)(nil)

// NewLDAPSIDResolver creates a new resolver with the given config
func NewLDAPSIDResolver(config LDAPConfig) (*LDAPSIDResolver, error) {
	var conn *ldap.Conn
	var err error

	// Connect to LDAP server
	conn, err = ldap.DialURL(config.Server)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP server: %w", err)
	}

	// Upgrade to TLS if requested and not already using ldaps://
	if config.UseTLS {
		err = conn.StartTLS(&tls.Config{InsecureSkipVerify: true})
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to start TLS: %w", err)
		}
	}

	// Bind to the server
	if config.BindDN != "" {
		err = conn.Bind(config.BindDN, config.Password)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to bind: %w", err)
		}
	}

	return &LDAPSIDResolver{
		config: config,
		conn:   conn,
		cache:  make(map[string]string),
	}, nil
}

// Resolve looks up a SID and returns the account name
func (r *LDAPSIDResolver) Resolve(sid *gontsd.SID) (string, error) {
	if sid == nil {
		return "", fmt.Errorf("nil SID")
	}

	// Check well-known SIDs first
	if name, ok := WellKnownSIDs[sid.Parsed]; ok {
		return name, nil
	}

	// Check cache
	r.mu.RLock()
	if name, ok := r.cache[sid.Parsed]; ok {
		r.mu.RUnlock()
		return name, nil
	}
	r.mu.RUnlock()

	// Query AD
	name, err := r.queryAD(sid)
	if err != nil {
		return "", err
	}

	// Cache result
	r.mu.Lock()
	r.cache[sid.Parsed] = name
	r.mu.Unlock()

	return name, nil
}

// ResolveBatch resolves multiple SIDs efficiently
func (r *LDAPSIDResolver) ResolveBatch(sids []*gontsd.SID) (map[string]string, error) {
	results := make(map[string]string)

	for _, sid := range sids {
		if sid == nil {
			continue
		}
		name, err := r.Resolve(sid)
		if err != nil {
			// Store error indicator but continue with other SIDs
			results[sid.Parsed] = fmt.Sprintf("<error: %v>", err)
		} else {
			results[sid.Parsed] = name
		}
	}

	return results, nil
}

func (r *LDAPSIDResolver) Close() error {
	if r.conn != nil {
		r.conn.Close()
	}
	return nil
}

// GetConn returns the underlying LDAP connection for use by other resolvers
func (r *LDAPSIDResolver) GetConn() *ldap.Conn {
	return r.conn
}

// queryAD queries Active Directory for the SID
func (r *LDAPSIDResolver) queryAD(sid *gontsd.SID) (string, error) {
	// Convert SID to binary format for LDAP query
	binarySID := sidToBinaryString(sid.Raw)

	// Search for the object with this SID
	searchRequest := ldap.NewSearchRequest(
		r.config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		fmt.Sprintf("(objectSid=%s)", binarySID),
		[]string{"sAMAccountName", "distinguishedName", "name"},
		nil,
	)

	sr, err := r.conn.Search(searchRequest)
	if err != nil {
		return "", fmt.Errorf("LDAP search failed: %w", err)
	}

	if len(sr.Entries) == 0 {
		return "", fmt.Errorf("SID not found in AD: %s", sid.Parsed)
	}

	entry := sr.Entries[0]

	// Build result with sAMAccountName and distinguishedName
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

// sidToBinaryString converts a raw SID to LDAP binary string format
// Each byte is escaped as \XX where XX is the hex value
func sidToBinaryString(raw []byte) string {
	result := ""
	for _, b := range raw {
		result += fmt.Sprintf("\\%02x", b)
	}
	return result
}

// SIDFromString parses a SID string (e.g., "S-1-5-21-...") and returns the binary representation
func SIDFromString(sidStr string) ([]byte, error) {
	var revision uint8
	var identifierAuthority uint64
	var subAuthorities []uint32

	// Parse the SID string
	var subAuthStr string
	n, err := fmt.Sscanf(sidStr, "S-%d-%d-%s", &revision, &identifierAuthority, &subAuthStr)
	if err != nil && n < 2 {
		return nil, fmt.Errorf("invalid SID format: %s", sidStr)
	}

	// Parse sub-authorities if present
	if n >= 3 && subAuthStr != "" {
		remaining := sidStr
		// Skip "S-R-IA-"
		for i := 0; i < 3; i++ {
			for j := 0; j < len(remaining); j++ {
				if remaining[j] == '-' {
					remaining = remaining[j+1:]
					break
				}
			}
		}

		// Parse remaining sub-authorities
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
