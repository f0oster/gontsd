package gontsd

// GUID represents a schema object GUID from a security descriptor.
type GUID struct {
	Raw string
}

func (g *GUID) String() string {
	if g == nil {
		return ""
	}
	return g.Raw
}
