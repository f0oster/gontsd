package resolve

import (
	"encoding/hex"
	"fmt"
	"strings"
	"sync"

	"github.com/go-ldap/ldap/v3"
)

// LDAPSchemaGUIDResolver queries Active Directory for GUID information
type LDAPSchemaGUIDResolver struct {
	conn   *ldap.Conn
	baseDN string
	cache  map[string]SchemaGUIDInfo
	mu     sync.RWMutex
}

var _ SchemaGUIDResolver = (*LDAPSchemaGUIDResolver)(nil)

// NewLDAPSchemaGUIDResolver creates a new GUID resolver using an existing LDAP connection
// The baseDN should be the root domain DN (e.g., "DC=example,DC=com")
// This resolver will preload extended rights at creation time for efficiency
func NewLDAPSchemaGUIDResolver(conn *ldap.Conn, baseDN string) (*LDAPSchemaGUIDResolver, error) {
	r := &LDAPSchemaGUIDResolver{
		conn:   conn,
		baseDN: baseDN,
		cache:  make(map[string]SchemaGUIDInfo),
	}

	if err := r.preloadExtendedRights(); err != nil {
		fmt.Printf("Warning: Failed to preload extended rights: %v\n", err)
	}

	return r, nil
}

// ResolveGUID looks up a GUID and returns full SchemaGUIDInfo
func (r *LDAPSchemaGUIDResolver) ResolveGUID(guid string) (*SchemaGUIDInfo, error) {
	normalizedGUID := NormalizeGUID(guid)

	r.mu.RLock()
	if info, ok := r.cache[normalizedGUID]; ok {
		r.mu.RUnlock()
		return &info, nil
	}
	r.mu.RUnlock()

	info, err := r.querySchema(normalizedGUID)
	if err == nil {
		r.cacheGUID(normalizedGUID, info)
		return &info, nil
	}

	return nil, ErrSchemaGUIDNotFound
}

// preloadExtendedRights queries CN=Extended-Rights,CN=Configuration and caches all results
func (r *LDAPSchemaGUIDResolver) preloadExtendedRights() error {
	configDN := fmt.Sprintf("CN=Extended-Rights,CN=Configuration,%s", r.baseDN)

	searchRequest := ldap.NewSearchRequest(
		configDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=controlAccessRight)",
		[]string{"displayName", "cn", "rightsGuid", "validAccesses", "appliesTo"},
		nil,
	)

	sr, err := r.conn.Search(searchRequest)
	if err != nil {
		return fmt.Errorf("LDAP search for extended rights failed: %w", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	for _, entry := range sr.Entries {
		rightsGuid := entry.GetAttributeValue("rightsGuid")
		if rightsGuid == "" {
			continue
		}

		normalizedGUID := NormalizeGUID(rightsGuid)
		name := entry.GetAttributeValue("displayName")
		if name == "" {
			name = entry.GetAttributeValue("cn")
		}

		// Determine type based on validAccesses
		guidType := determineExtendedRightType(entry.GetAttributeValue("validAccesses"))

		appliesToGUIDs := entry.GetAttributeValues("appliesTo")
		var appliesTo []string
		for _, classGUID := range appliesToGUIDs {
			normalizedClassGUID := NormalizeGUID(classGUID)
			appliesTo = append(appliesTo, normalizedClassGUID)
		}

		r.cache[normalizedGUID] = SchemaGUIDInfo{
			Name:      name,
			Type:      guidType,
			GUID:      normalizedGUID,
			AppliesTo: appliesTo,
		}
	}

	return nil
}

// ResolveAppliesTo resolves the AppliesTo GUIDs to class names
func (r *LDAPSchemaGUIDResolver) ResolveAppliesTo(info *SchemaGUIDInfo) []string {
	if info == nil || len(info.AppliesTo) == 0 {
		return nil
	}

	resolved := make([]string, 0, len(info.AppliesTo))
	for _, classGUID := range info.AppliesTo {
		// Try to resolve the class GUID to a name
		classInfo, err := r.ResolveGUID(classGUID)
		if err == nil && classInfo.Name != "" {
			resolved = append(resolved, classInfo.Name)
		} else {
			// Keep the GUID if we can't resolve it
			resolved = append(resolved, classGUID)
		}
	}
	return resolved
}

// querySchema queries CN=Schema,CN=Configuration for attribute/class GUIDs
func (r *LDAPSchemaGUIDResolver) querySchema(guid string) (SchemaGUIDInfo, error) {
	schemaDN := fmt.Sprintf("CN=Schema,CN=Configuration,%s", r.baseDN)

	// schemaIDGUID is stored as binary, need to convert GUID string to binary escape format
	binaryFilter := guidStringToBinaryFilter(guid)

	searchRequest := ldap.NewSearchRequest(
		schemaDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1, 0, false,
		fmt.Sprintf("(schemaIDGUID=%s)", binaryFilter),
		[]string{"ldapDisplayName", "cn", "objectClass"},
		nil,
	)

	sr, err := r.conn.Search(searchRequest)
	if err != nil {
		return SchemaGUIDInfo{}, fmt.Errorf("LDAP schema search failed: %w", err)
	}

	if len(sr.Entries) == 0 {
		return SchemaGUIDInfo{}, ErrSchemaGUIDNotFound
	}

	entry := sr.Entries[0]
	name := entry.GetAttributeValue("ldapDisplayName")
	if name == "" {
		name = entry.GetAttributeValue("cn")
	}

	// Determine if this is an attribute or class
	guidType := GUIDTypeAttribute
	for _, oc := range entry.GetAttributeValues("objectClass") {
		if oc == "classSchema" {
			guidType = GUIDTypeClass
			break
		}
	}

	return SchemaGUIDInfo{
		Name: name,
		Type: guidType,
		GUID: guid,
	}, nil
}

// cacheGUID adds a GUID info to the cache
func (r *LDAPSchemaGUIDResolver) cacheGUID(guid string, info SchemaGUIDInfo) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache[guid] = info
}

func determineExtendedRightType(validAccesses string) string {
	switch validAccesses {
	case "256":
		return GUIDTypeExtendedRight
	case "8":
		return GUIDTypeValidatedWrite
	case "48":
		return GUIDTypePropertySet
	default:
		return GUIDTypeExtendedRight
	}
}

func guidStringToBinaryFilter(guid string) string {
	clean := strings.ReplaceAll(guid, "-", "")
	if len(clean) != 32 {
		return ""
	}

	bytes, err := hex.DecodeString(clean)
	if err != nil {
		return ""
	}

	bytes[0], bytes[1], bytes[2], bytes[3] = bytes[3], bytes[2], bytes[1], bytes[0]
	bytes[4], bytes[5] = bytes[5], bytes[4]
	bytes[6], bytes[7] = bytes[7], bytes[6]

	var result strings.Builder
	for _, b := range bytes {
		result.WriteString(fmt.Sprintf("\\%02x", b))
	}
	return result.String()
}

func (r *LDAPSchemaGUIDResolver) ClearCache() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache = make(map[string]SchemaGUIDInfo)
}

func (r *LDAPSchemaGUIDResolver) CacheSize() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.cache)
}
