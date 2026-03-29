package ldapresolver

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

const defaultMaxCacheSize = 10000

// LDAPSIDResolver resolves SIDs by querying Active Directory.
type LDAPSIDResolver struct {
	client       *LDAPClient
	cache        map[string]string // SID string -> resolved name
	mu           sync.RWMutex
	maxCacheSize int
}

var _ gontsd.SIDResolver = (*LDAPSIDResolver)(nil)

// NewLDAPSIDResolver creates a new LDAP-backed SID resolver.
func NewLDAPSIDResolver(client *LDAPClient, opts ...SIDResolverOption) *LDAPSIDResolver {
	r := &LDAPSIDResolver{
		client:       client,
		cache:        make(map[string]string),
		maxCacheSize: defaultMaxCacheSize,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// SIDResolverOption configures an LDAPSIDResolver.
type SIDResolverOption func(*LDAPSIDResolver)

// WithMaxSIDCacheSize sets the maximum number of cached SID resolutions.
// When exceeded, the cache is cleared. Default is 10,000.
func WithMaxSIDCacheSize(n int) SIDResolverOption {
	return func(r *LDAPSIDResolver) {
		r.maxCacheSize = n
	}
}

func (r *LDAPSIDResolver) Resolve(sid *gontsd.SID) (string, error) {
	if sid == nil {
		return "", fmt.Errorf("nil SID")
	}

	r.mu.RLock()
	if name, ok := r.cache[sid.Value]; ok {
		r.mu.RUnlock()
		return name, nil
	}
	r.mu.RUnlock()

	name, err := r.queryAD(sid)
	if err != nil {
		return "", err
	}

	r.cacheSID(sid.Value, name)

	return name, nil
}

const maxSIDsPerQuery = 50

// ResolveBatch resolves multiple SIDs, using a single LDAP query per batch
// of uncached SIDs. Results are keyed by SID string (e.g. "S-1-5-21-...").
func (r *LDAPSIDResolver) ResolveBatch(sids []*gontsd.SID) map[string]gontsd.SIDResult {
	results := make(map[string]gontsd.SIDResult, len(sids))

	// Partition into cached/resolved and needing LDAP lookup.
	var needQuery []*gontsd.SID
	r.mu.RLock()
	for _, sid := range sids {
		if sid == nil {
			continue
		}
		if name, ok := r.cache[sid.Value]; ok {
			results[sid.Value] = gontsd.SIDResult{Name: name}
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

func (r *LDAPSIDResolver) queryBatch(sids []*gontsd.SID, results map[string]gontsd.SIDResult) {
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
			results[sid.Value] = gontsd.SIDResult{Err: fmt.Errorf("LDAP search failed: %w", err)}
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
		found[sid.Value] = true

		resolvedName := extractName(entry)
		results[sid.Value] = gontsd.SIDResult{Name: resolvedName}

		r.cacheSID(sid.Value, resolvedName)
	}

	// Mark SIDs with no LDAP result.
	for _, sid := range sids {
		if !found[sid.Value] {
			results[sid.Value] = gontsd.SIDResult{Err: fmt.Errorf("SID not found in AD: %s", sid.Value)}
		}
	}
}

func extractName(entry *ldap.Entry) string {
	if samName := entry.GetAttributeValue("sAMAccountName"); samName != "" {
		return samName
	}
	if name := entry.GetAttributeValue("name"); name != "" {
		return name
	}
	if dn := entry.GetAttributeValue("distinguishedName"); dn != "" {
		return dn
	}
	return ""
}

func (r *LDAPSIDResolver) cacheSID(parsed, name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.maxCacheSize > 0 && len(r.cache) >= r.maxCacheSize {
		clear(r.cache)
	}
	r.cache[parsed] = name
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
		return "", fmt.Errorf("SID not found in AD: %s", sid.Value)
	}

	name := extractName(sr.Entries[0])
	if name == "" {
		return "", fmt.Errorf("no name attributes found for SID: %s", sid.Value)
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
