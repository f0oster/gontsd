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

const maxSIDsPerQuery = 50

// SIDResult holds the outcome of resolving a single SID.
type SIDResult struct {
	Name string
	Err  error
}

// ResolveBatch resolves multiple SIDs, using a single LDAP query per batch
// of uncached SIDs. Results are keyed by SID string (e.g. "S-1-5-21-...").
func (r *LDAPSIDResolver) ResolveBatch(sids []*gontsd.SID) map[string]SIDResult {
	results := make(map[string]SIDResult, len(sids))

	// Partition into cached/resolved and needing LDAP lookup.
	var needQuery []*gontsd.SID
	r.mu.RLock()
	for _, sid := range sids {
		if sid == nil {
			continue
		}
		if name, ok := r.cache[sid.Parsed]; ok {
			results[sid.Parsed] = SIDResult{Name: name}
		} else {
			needQuery = append(needQuery, sid)
		}
	}
	r.mu.RUnlock()

	// Batch LDAP queries in groups.
	for i := 0; i < len(needQuery); i += maxSIDsPerQuery {
		end := i + maxSIDsPerQuery
		if end > len(needQuery) {
			end = len(needQuery)
		}
		r.queryBatch(needQuery[i:end], results)
	}

	return results
}

func (r *LDAPSIDResolver) queryBatch(sids []*gontsd.SID, results map[string]SIDResult) {
	if len(sids) == 0 {
		return
	}

	// Build OR filter: (|(objectSid=\xx...)(...))
	sidByBinary := make(map[string]*gontsd.SID, len(sids))
	var filterParts []string
	for _, sid := range sids {
		binarySID := sidToBinaryString(sid.Raw)
		sidByBinary[binarySID] = sid
		filterParts = append(filterParts, fmt.Sprintf("(objectSid=%s)", binarySID))
	}

	filter := filterParts[0]
	if len(filterParts) > 1 {
		filter = fmt.Sprintf("(|%s)", strings.Join(filterParts, ""))
	}

	searchRequest := ldap.NewSearchRequest(
		r.client.BaseDN(),
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		filter,
		[]string{"objectSid", "sAMAccountName", "distinguishedName", "name"},
		nil,
	)

	sr, err := r.client.Conn().Search(searchRequest)
	if err != nil {
		// Mark all SIDs in this batch as failed.
		for _, sid := range sids {
			results[sid.Parsed] = SIDResult{Err: fmt.Errorf("LDAP search failed: %w", err)}
		}
		return
	}

	// Map results back by matching objectSid.
	found := make(map[string]bool)
	for _, entry := range sr.Entries {
		rawSid := entry.GetRawAttributeValue("objectSid")
		binarySID := sidToBinaryString(rawSid)
		sid, ok := sidByBinary[binarySID]
		if !ok {
			continue
		}
		found[sid.Parsed] = true

		resolvedName := extractName(entry)
		results[sid.Parsed] = SIDResult{Name: resolvedName}

		r.mu.Lock()
		r.cache[sid.Parsed] = resolvedName
		r.mu.Unlock()
	}

	// Mark SIDs with no LDAP result.
	for _, sid := range sids {
		if !found[sid.Parsed] {
			results[sid.Parsed] = SIDResult{Err: fmt.Errorf("SID not found in AD: %s", sid.Parsed)}
		}
	}
}

func extractName(entry *ldap.Entry) string {
	samName := entry.GetAttributeValue("sAMAccountName")
	dn := entry.GetAttributeValue("distinguishedName")
	if samName != "" && dn != "" {
		return fmt.Sprintf("%s (%s)", samName, dn)
	}
	if samName != "" {
		return samName
	}
	if dn != "" {
		return dn
	}
	if name := entry.GetAttributeValue("name"); name != "" {
		return name
	}
	return ""
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

	name := extractName(sr.Entries[0])
	if name == "" {
		return "", fmt.Errorf("no name attributes found for SID: %s", sid.Parsed)
	}
	return name, nil
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
