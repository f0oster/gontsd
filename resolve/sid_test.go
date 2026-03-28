package resolve

import (
	"testing"

	"github.com/f0oster/gontsd"
)

func TestWellKnownSIDResolver(t *testing.T) {
	r := WellKnownSIDResolver{}

	// Exact match
	name, err := r.Resolve(&gontsd.SID{Parsed: "S-1-5-18"})
	if err != nil {
		t.Fatalf("Resolve(S-1-5-18) error: %v", err)
	}
	if name != "Local System" {
		t.Errorf("Resolve(S-1-5-18) = %q, want %q", name, "Local System")
	}

	// Domain-relative RID matching
	name, err = r.Resolve(&gontsd.SID{Parsed: "S-1-5-21-75115020-4145467708-3593911600-512"})
	if err != nil {
		t.Fatalf("Resolve(domain admin) error: %v", err)
	}
	if name != "Domain Admins" {
		t.Errorf("Resolve(domain admin) = %q, want %q", name, "Domain Admins")
	}

	// Domain-relative RID with different domain identifier
	name, err = r.Resolve(&gontsd.SID{Parsed: "S-1-5-21-999999-888888-777777-500"})
	if err != nil {
		t.Fatalf("Resolve(administrator) error: %v", err)
	}
	if name != "Administrator" {
		t.Errorf("Resolve(administrator) = %q, want %q", name, "Administrator")
	}

	// Unknown domain RID
	_, err = r.Resolve(&gontsd.SID{Parsed: "S-1-5-21-1-2-3-9999"})
	if err == nil {
		t.Error("expected error for unknown domain RID")
	}

	// Nil SID
	_, err = r.Resolve(nil)
	if err == nil {
		t.Error("expected error for nil SID")
	}
}

func TestResolveBatchSIDs_Fallback(t *testing.T) {
	// WellKnownSIDResolver doesn't implement BatchSIDResolver,
	// so ResolveBatchSIDs should fall back to individual Resolve calls.
	resolver := WellKnownSIDResolver{}
	sids := []*gontsd.SID{
		{Parsed: "S-1-5-18"},
		{Parsed: "S-1-1-0"},
		{Parsed: "S-1-5-21-1-2-3-99999"}, // unknown
		nil,                                // should be skipped
	}

	results := ResolveBatchSIDs(resolver, sids)

	if r, ok := results["S-1-5-18"]; !ok || r.Err != nil || r.Name != "Local System" {
		t.Errorf("S-1-5-18 result = %+v, want Local System", results["S-1-5-18"])
	}
	if r, ok := results["S-1-1-0"]; !ok || r.Err != nil || r.Name != "Everyone" {
		t.Errorf("S-1-1-0 result = %+v, want Everyone", results["S-1-1-0"])
	}
	if r, ok := results["S-1-5-21-1-2-3-99999"]; !ok || r.Err == nil {
		t.Errorf("unknown SID result = %+v, want error", r)
	}
	if _, ok := results[""]; ok {
		t.Error("nil SID should not produce a result")
	}
}
