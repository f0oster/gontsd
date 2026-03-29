package gontsd

// GUID represents a schema object GUID from a security descriptor.
type GUID struct {
	Raw string

	resolver SchemaGUIDResolver
}

func (g *GUID) String() string {
	if g == nil {
		return ""
	}
	return g.Raw
}

// Resolved returns the resolved display name if a resolver was set
// during parsing, e.g. "User-Force-Change-Password".
// Falls back to the raw GUID string if unresolved.
func (g *GUID) Resolved() string {
	if g == nil {
		return ""
	}
	if g.resolver != nil {
		return FormatGUID(g.Raw, g.resolver)
	}
	return g.Raw
}
