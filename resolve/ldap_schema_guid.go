package resolve

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
func NewLDAPSchemaGUIDResolver(client *LDAPClient) (*LDAPSchemaGUIDResolver, error) {
	r := &LDAPSchemaGUIDResolver{
		client: client,
		cache:  make(map[string]SchemaGUIDInfo),
	}

	if err := r.preloadExtendedRights(); err != nil {
		fmt.Printf("Warning: Failed to preload extended rights: %v\n", err)
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
	if err == nil {
		r.cacheGUID(normalizedGUID, info)
		return &info, nil
	}

	return nil, ErrSchemaGUIDNotFound
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

	sr, err := r.client.Conn().Search(searchRequest)
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

func (r *LDAPSchemaGUIDResolver) ResolveAppliesTo(info *SchemaGUIDInfo) []string {
	if info == nil || len(info.AppliesTo) == 0 {
		return nil
	}

	resolved := make([]string, 0, len(info.AppliesTo))
	for _, classGUID := range info.AppliesTo {
		classInfo, err := r.ResolveGUID(classGUID)
		if err == nil && classInfo.Name != "" {
			resolved = append(resolved, classInfo.Name)
		} else {
			resolved = append(resolved, classGUID)
		}
	}
	return resolved
}

func (r *LDAPSchemaGUIDResolver) querySchema(guid string) (SchemaGUIDInfo, error) {
	schemaDN := fmt.Sprintf("CN=Schema,CN=Configuration,%s", r.client.BaseDN())

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
