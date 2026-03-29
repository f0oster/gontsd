package gontsd

import (
	"encoding/hex"
	"fmt"
	"strings"
	"sync"

	"github.com/go-ldap/ldap/v3"
)

// LDAPSchemaGUIDResolver resolves schema GUIDs by querying Active Directory.
type LDAPSchemaGUIDResolver struct {
	client *LDAPClient
	cache  map[string]SchemaGUIDInfo
	mu     sync.RWMutex
}

var _ SchemaGUIDResolver = (*LDAPSchemaGUIDResolver)(nil)

// NewLDAPSchemaGUIDResolver creates a new LDAP-backed schema GUID resolver.
// It preloads schema classes and extended rights from AD so that subsequent
// lookups can be resolved from cache.
func NewLDAPSchemaGUIDResolver(client *LDAPClient) (*LDAPSchemaGUIDResolver, error) {
	r := &LDAPSchemaGUIDResolver{
		client: client,
		cache:  make(map[string]SchemaGUIDInfo),
	}

	if err := r.preloadSchema(); err != nil {
		return nil, fmt.Errorf("failed to preload schema: %w", err)
	}

	if err := r.preloadExtendedRights(); err != nil {
		return nil, fmt.Errorf("failed to preload extended rights: %w", err)
	}

	return r, nil
}

func (r *LDAPSchemaGUIDResolver) ResolveGUID(guid string) (*SchemaGUIDInfo, error) {
	normalizedGUID := NormalizeGUID(guid)

	r.mu.RLock()
	if info, ok := r.cache[normalizedGUID]; ok {
		r.mu.RUnlock()
		return &info, nil
	}
	r.mu.RUnlock()

	info, err := r.querySchema(normalizedGUID)
	if err != nil {
		return nil, err
	}
	r.cacheGUID(normalizedGUID, info)
	return &info, nil
}

func (r *LDAPSchemaGUIDResolver) preloadSchema() error {
	schemaDN := fmt.Sprintf("CN=Schema,CN=Configuration,%s", r.client.BaseDN())

	searchRequest := ldap.NewSearchRequest(
		schemaDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(|(objectClass=classSchema)(objectClass=attributeSchema))",
		[]string{"schemaIDGUID", "ldapDisplayName", "cn", "objectClass"},
		nil,
	)

	sr, err := r.client.Conn().SearchWithPaging(searchRequest, 1000)
	if err != nil {
		return fmt.Errorf("LDAP schema search failed: %w", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	for _, entry := range sr.Entries {
		rawGUID := entry.GetRawAttributeValue("schemaIDGUID")
		if len(rawGUID) != 16 {
			continue
		}

		guidStr, err := GUIDBytesToString(rawGUID)
		if err != nil {
			continue
		}
		normalizedGUID := NormalizeGUID(guidStr)

		name := entry.GetAttributeValue("ldapDisplayName")
		if name == "" {
			name = entry.GetAttributeValue("cn")
		}

		guidType := GUIDTypeAttribute
		for _, oc := range entry.GetAttributeValues("objectClass") {
			if oc == "classSchema" {
				guidType = GUIDTypeClass
				break
			}
		}

		r.cache[normalizedGUID] = SchemaGUIDInfo{
			Name: name,
			Type: guidType,
			GUID: normalizedGUID,
		}
	}

	return nil
}

func (r *LDAPSchemaGUIDResolver) preloadExtendedRights() error {
	configDN := fmt.Sprintf("CN=Extended-Rights,CN=Configuration,%s", r.client.BaseDN())

	searchRequest := ldap.NewSearchRequest(
		configDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=controlAccessRight)",
		[]string{"displayName", "cn", "rightsGuid", "validAccesses", "appliesTo"},
		nil,
	)

	sr, err := r.client.Conn().SearchWithPaging(searchRequest, 1000)
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

		guidType := determineExtendedRightType(entry.GetAttributeValue("validAccesses"))

		appliesToGUIDs := entry.GetAttributeValues("appliesTo")
		var appliesTo []AppliesToEntry
		for _, classGUID := range appliesToGUIDs {
			normalized := NormalizeGUID(classGUID)
			ae := AppliesToEntry{GUID: normalized}
			if cached, ok := r.cache[normalized]; ok {
				ae.Name = cached.Name
			}
			appliesTo = append(appliesTo, ae)
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

func (r *LDAPSchemaGUIDResolver) querySchema(guid string) (SchemaGUIDInfo, error) {
	schemaDN := fmt.Sprintf("CN=Schema,CN=Configuration,%s", r.client.BaseDN())

	binaryFilter, err := guidStringToBinaryFilter(guid)
	if err != nil {
		return SchemaGUIDInfo{}, fmt.Errorf("invalid GUID %q: %w", guid, err)
	}

	searchRequest := ldap.NewSearchRequest(
		schemaDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1, 0, false,
		fmt.Sprintf("(schemaIDGUID=%s)", binaryFilter),
		[]string{"ldapDisplayName", "cn", "objectClass"},
		nil,
	)

	sr, err := r.client.Conn().Search(searchRequest)
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

func (r *LDAPSchemaGUIDResolver) cacheGUID(guid string, info SchemaGUIDInfo) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache[guid] = info
}

func determineExtendedRightType(validAccesses string) GUIDType {
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

func guidStringToBinaryFilter(guid string) (string, error) {
	clean := strings.ReplaceAll(guid, "-", "")
	if len(clean) != 32 {
		return "", fmt.Errorf("invalid GUID length: expected 32 hex chars, got %d", len(clean))
	}

	bytes, err := hex.DecodeString(clean)
	if err != nil {
		return "", fmt.Errorf("invalid GUID hex: %w", err)
	}

	bytes[0], bytes[1], bytes[2], bytes[3] = bytes[3], bytes[2], bytes[1], bytes[0]
	bytes[4], bytes[5] = bytes[5], bytes[4]
	bytes[6], bytes[7] = bytes[7], bytes[6]

	var result strings.Builder
	for _, b := range bytes {
		result.WriteString(fmt.Sprintf("\\%02x", b))
	}
	return result.String(), nil
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
