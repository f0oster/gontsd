package gontsd

// GUID represents a schema object GUID from a security descriptor.
type GUID struct {
	Raw         string
	Name        string   // resolved name, e.g. "User-Force-Change-Password"
	Type        GUIDType // e.g. GUIDTypeExtendedRight, GUIDTypeClass
	Description string   // security-relevant description

	resolver SchemaGUIDResolver
}

func (g *GUID) String() string {
	if g == nil {
		return ""
	}
	return g.Raw
}

// Resolved returns the resolved name if available, falling back to the raw GUID string.
func (g *GUID) Resolved() string {
	if g == nil {
		return ""
	}
	if g.Name != "" {
		return g.Name
	}
	return g.Raw
}
