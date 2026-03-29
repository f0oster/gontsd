package gontsd

import (
	"errors"
	"strings"
)

// ErrSchemaGUIDNotFound is returned when a GUID cannot be resolved.
var ErrSchemaGUIDNotFound = errors.New("GUID not found")

// AppliesToEntry represents a schema class that an extended right applies to.
type AppliesToEntry struct {
	GUID string
	Name string
}

// SchemaGUIDInfo contains metadata about a resolved schema GUID.
type SchemaGUIDInfo struct {
	Name        string
	Type        GUIDType
	GUID        string
	Description string
	AppliesTo   []AppliesToEntry
}

func (e AppliesToEntry) String() string {
	if e.Name != "" {
		return e.Name
	}
	return e.GUID
}

func (info SchemaGUIDInfo) String() string {
	if info.Name != "" {
		return info.Name
	}
	return info.GUID
}

// FormatAppliesTo returns the AppliesTo entries as a comma-separated string
// of names, falling back to GUIDs for unresolved entries.
func (info SchemaGUIDInfo) FormatAppliesTo() string {
	names := make([]string, len(info.AppliesTo))
	for i, entry := range info.AppliesTo {
		names[i] = entry.String()
	}
	return strings.Join(names, ", ")
}

// SchemaGUIDResolver resolves schema GUIDs to human-readable names and metadata.
// Implementations include [WellKnownSchemaGUIDResolver] for well-known schema
// classes, attributes, and extended rights, [LDAPSchemaGUIDResolver] for Active
// Directory schema lookups, and [ChainSchemaGUIDResolver] to try multiple
// resolvers in order.
type SchemaGUIDResolver interface {
	ResolveGUID(guid string) (*SchemaGUIDInfo, error)
}

// FormatGUID resolves a GUID using the given resolver and returns a
// display string like "Name (GUID) [type]". If the GUID cannot be
// resolved, it returns the raw GUID string.
func FormatGUID(guid string, resolver SchemaGUIDResolver) string {
	info, err := resolver.ResolveGUID(guid)
	if err != nil {
		return guid
	}
	return info.String()
}

// NormalizeGUID converts a GUID to uppercase for consistent comparison.
func NormalizeGUID(guid string) string {
	return strings.ToUpper(guid)
}

// NoOpSchemaGUIDResolver is a resolver that always returns ErrSchemaGUIDNotFound.
type NoOpSchemaGUIDResolver struct{}

func (NoOpSchemaGUIDResolver) ResolveGUID(guid string) (*SchemaGUIDInfo, error) {
	return nil, ErrSchemaGUIDNotFound
}

// ChainSchemaGUIDResolver tries multiple resolvers in order until one succeeds.
type ChainSchemaGUIDResolver struct {
	Resolvers []SchemaGUIDResolver
}

func (c ChainSchemaGUIDResolver) ResolveGUID(guid string) (*SchemaGUIDInfo, error) {
	for _, r := range c.Resolvers {
		info, err := r.ResolveGUID(guid)
		if err == nil {
			return info, nil
		}
	}
	return nil, ErrSchemaGUIDNotFound
}

// WellKnownSchemaGUIDResolver resolves GUIDs using a built-in table of well-known values.
type WellKnownSchemaGUIDResolver struct{}

func (WellKnownSchemaGUIDResolver) ResolveGUID(guid string) (*SchemaGUIDInfo, error) {
	normalizedGUID := NormalizeGUID(guid)
	if info, ok := WellKnownSchemaGUIDs[normalizedGUID]; ok {
		return &info, nil
	}
	return nil, ErrSchemaGUIDNotFound
}

// Well-known GUIDs for extended rights, property sets, and schema objects
//
// Security-relevant descriptions are sourced from:
//
// Microsoft Official Documentation:
//   - Extended Rights Reference: https://learn.microsoft.com/en-us/windows/win32/adschema/extended-rights
//   - Control Access Rights: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1522b774-6464-41a3-87a5-1e5633c3fbbb
//   - DS-Replication-Get-Changes: https://learn.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-get-changes
//   - DS-Replication-Get-Changes-All: https://learn.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-get-changes-all
//
// Security Research & Attack Techniques:
//   - DCSync: https://adsecurity.org/?p=1729 (Sean Metcalf)
//   - Kerberoasting: https://attack.mitre.org/techniques/T1558/003/ (MITRE ATT&CK)
//   - Shadow Credentials: https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab (Elad Shamir)
//   - RBCD Attacks: https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd (The Hacker Recipes)
//   - AD Certificate Services: https://posts.specterops.io/certified-pre-owned-d95910965cd2 (Will Schroeder & Lee Christensen)

// GUIDType represents the category of a schema GUID.
type GUIDType string

const (
	GUIDTypeExtendedRight  GUIDType = "extendedRight"
	GUIDTypePropertySet    GUIDType = "propertySet"
	GUIDTypeAttribute      GUIDType = "attribute"
	GUIDTypeClass          GUIDType = "class"
	GUIDTypeValidatedWrite GUIDType = "validatedWrite"
)

var WellKnownSchemaGUIDs = map[string]SchemaGUIDInfo{
	// Extended Rights - Control Access Rights
	// https://learn.microsoft.com/en-us/windows/win32/adschema/extended-rights

	// DCSync-related rights (critical for security)
	// Ref: https://learn.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-get-changes
	// Security: https://adsecurity.org/?p=1729
	"1131F6AA-9C07-11D1-F79F-00C04FC2DCD2": {
		Name:        "DS-Replication-Get-Changes",
		Type:        GUIDTypeExtendedRight,
		GUID:        "1131F6AA-9C07-11D1-F79F-00C04FC2DCD2",
		Description: "Replicate directory changes from a naming context. Required for DCSync attacks.",
		AppliesTo:   []AppliesToEntry{{GUID: "19195A5B-6DA0-11D0-AFA3-00C04FD930C9", Name: "Domain-DNS"}, {GUID: "3FDF05A1-9DCD-11D1-A9C5-0000F80367C1", Name: "Configuration"}, {GUID: "BF967A91-0DE6-11D0-A285-00AA003049E2", Name: "DMD"}},
	},
	// Ref: https://learn.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-get-changes-all
	"1131F6AD-9C07-11D1-F79F-00C04FC2DCD2": {
		Name:        "DS-Replication-Get-Changes-All",
		Type:        GUIDTypeExtendedRight,
		GUID:        "1131F6AD-9C07-11D1-F79F-00C04FC2DCD2",
		Description: "Replicate all directory changes including secrets (passwords). Critical for DCSync.",
		AppliesTo:   []AppliesToEntry{{GUID: "19195A5B-6DA0-11D0-AFA3-00C04FD930C9", Name: "Domain-DNS"}, {GUID: "3FDF05A1-9DCD-11D1-A9C5-0000F80367C1", Name: "Configuration"}, {GUID: "BF967A91-0DE6-11D0-A285-00AA003049E2", Name: "DMD"}},
	},
	"89E95B76-444D-4C62-991A-0FACBEDA640C": {
		Name:        "DS-Replication-Get-Changes-In-Filtered-Set",
		Type:        GUIDTypeExtendedRight,
		GUID:        "89E95B76-444D-4C62-991A-0FACBEDA640C",
		Description: "Replicate directory changes in a filtered set (Read-Only Domain Controllers).",
		AppliesTo:   []AppliesToEntry{{GUID: "19195A5B-6DA0-11D0-AFA3-00C04FD930C9", Name: "Domain-DNS"}, {GUID: "3FDF05A1-9DCD-11D1-A9C5-0000F80367C1", Name: "Configuration"}, {GUID: "BF967A91-0DE6-11D0-A285-00AA003049E2", Name: "DMD"}},
	},
	"1131F6AB-9C07-11D1-F79F-00C04FC2DCD2": {
		Name:        "DS-Replication-Manage-Topology",
		Type:        GUIDTypeExtendedRight,
		GUID:        "1131F6AB-9C07-11D1-F79F-00C04FC2DCD2",
		Description: "Manage replication topology and trigger replication between domain controllers.",
		AppliesTo:   []AppliesToEntry{{GUID: "19195A5B-6DA0-11D0-AFA3-00C04FD930C9", Name: "Domain-DNS"}, {GUID: "3FDF05A1-9DCD-11D1-A9C5-0000F80367C1", Name: "Configuration"}, {GUID: "BF967A91-0DE6-11D0-A285-00AA003049E2", Name: "DMD"}},
	},
	"1131F6AC-9C07-11D1-F79F-00C04FC2DCD2": {
		Name:        "DS-Replication-Synchronize",
		Type:        GUIDTypeExtendedRight,
		GUID:        "1131F6AC-9C07-11D1-F79F-00C04FC2DCD2",
		Description: "Synchronize replication with a naming context.",
		AppliesTo:   []AppliesToEntry{{GUID: "19195A5B-6DA0-11D0-AFA3-00C04FD930C9", Name: "Domain-DNS"}, {GUID: "3FDF05A1-9DCD-11D1-A9C5-0000F80367C1", Name: "Configuration"}, {GUID: "BF967A91-0DE6-11D0-A285-00AA003049E2", Name: "DMD"}},
	},

	// Password and credential-related rights
	"00299570-246D-11D0-A768-00AA006E0529": {
		Name:        "User-Force-Change-Password",
		Type:        GUIDTypeExtendedRight,
		GUID:        "00299570-246D-11D0-A768-00AA006E0529",
		Description: "Reset a user's password without knowing the current password.",
		AppliesTo:   []AppliesToEntry{{GUID: "BF967ABA-0DE6-11D0-A285-00AA003049E2", Name: "User"}, {GUID: "BF967A86-0DE6-11D0-A285-00AA003049E2", Name: "Computer"}, {GUID: "CE206244-5827-4A86-BA1C-1C0C386C1B64", Name: "ms-DS-Group-Managed-Service-Account"}},
	},
	"AB721A53-1E2F-11D0-9819-00AA0040529B": {
		Name:        "User-Change-Password",
		Type:        GUIDTypeExtendedRight,
		GUID:        "AB721A53-1E2F-11D0-9819-00AA0040529B",
		Description: "Change own password (requires knowing current password).",
		AppliesTo:   []AppliesToEntry{{GUID: "BF967ABA-0DE6-11D0-A285-00AA003049E2", Name: "User"}, {GUID: "BF967A86-0DE6-11D0-A285-00AA003049E2", Name: "Computer"}, {GUID: "CE206244-5827-4A86-BA1C-1C0C386C1B64", Name: "ms-DS-Group-Managed-Service-Account"}},
	},
	"280F369C-67C7-438E-AE98-1D46F3C6F541": {
		Name:        "Unexpire-Password",
		Type:        GUIDTypeExtendedRight,
		GUID:        "280F369C-67C7-438E-AE98-1D46F3C6F541",
		Description: "Unexpire a user's password.",
		AppliesTo:   []AppliesToEntry{{GUID: "19195A5B-6DA0-11D0-AFA3-00C04FD930C9", Name: "Domain-DNS"}},
	},
	"CCC2DC7D-A6AD-4A7A-8846-C04E3CC53501": {
		Name:        "Unexpire-Password (Alt)",
		Type:        GUIDTypeExtendedRight,
		GUID:        "CCC2DC7D-A6AD-4A7A-8846-C04E3CC53501",
		Description: "Unexpire a user's password (alternate GUID).",
	},

	// Send-As and Receive-As (Exchange-related)
	"AB721A54-1E2F-11D0-9819-00AA0040529B": {
		Name:        "Send-As",
		Type:        GUIDTypeExtendedRight,
		GUID:        "AB721A54-1E2F-11D0-9819-00AA0040529B",
		Description: "Send email as another user. Allows impersonation in Exchange.",
		AppliesTo:   []AppliesToEntry{{GUID: "BF967ABA-0DE6-11D0-A285-00AA003049E2", Name: "User"}, {GUID: "BF967A86-0DE6-11D0-A285-00AA003049E2", Name: "Computer"}},
	},
	"AB721A56-1E2F-11D0-9819-00AA0040529B": {
		Name:        "Receive-As",
		Type:        GUIDTypeExtendedRight,
		GUID:        "AB721A56-1E2F-11D0-9819-00AA0040529B",
		Description: "Receive email as another user. Allows reading another user's mailbox.",
		AppliesTo:   []AppliesToEntry{{GUID: "BF967ABA-0DE6-11D0-A285-00AA003049E2", Name: "User"}, {GUID: "BF967A86-0DE6-11D0-A285-00AA003049E2", Name: "Computer"}},
	},

	// Certificate enrollment
	// Security: https://posts.specterops.io/certified-pre-owned-d95910965cd2
	"0E10C968-78FB-11D2-90D4-00C04F79DC55": {
		Name:        "Certificate-Enrollment",
		Type:        GUIDTypeExtendedRight,
		GUID:        "0E10C968-78FB-11D2-90D4-00C04F79DC55",
		Description: "Enroll for certificates from a Certificate Authority. Can enable privilege escalation via ADCS.",
		AppliesTo:   []AppliesToEntry{{GUID: "E0FA1E8C-9B45-11D0-AFDD-00C04FD930C9", Name: "PKI-Certificate-Template"}},
	},
	"A05B8CC2-17BC-4802-A710-E7C15AB866A2": {
		Name:        "Certificate-AutoEnrollment",
		Type:        GUIDTypeExtendedRight,
		GUID:        "A05B8CC2-17BC-4802-A710-E7C15AB866A2",
		Description: "Automatically enroll for certificates from a Certificate Authority.",
		AppliesTo:   []AppliesToEntry{{GUID: "E0FA1E8C-9B45-11D0-AFDD-00C04FD930C9", Name: "PKI-Certificate-Template"}},
	},

	// Domain operations
	"1131F6AE-9C07-11D1-F79F-00C04FC2DCD2": {Name: "DS-Check-Stale-Phantoms", Type: GUIDTypeExtendedRight, GUID: "1131F6AE-9C07-11D1-F79F-00C04FC2DCD2", Description: "Check for and remove stale phantom objects in the directory."},
	"69AE6200-7F46-11D2-B9AD-00C04F79F805": {Name: "DS-Check-Stale-Phantoms (Alt)", Type: GUIDTypeExtendedRight, GUID: "69AE6200-7F46-11D2-B9AD-00C04F79F805", Description: "Check for and remove stale phantom objects in the directory."},
	"2F16C4A5-B98E-432C-952A-CB388BA33F2E": {Name: "DS-Execute-Intentions-Script", Type: GUIDTypeExtendedRight, GUID: "2F16C4A5-B98E-432C-952A-CB388BA33F2E", Description: "Execute AD intentions scripts during schema updates."},
	"9923A32A-3607-11D2-B9BE-0000F87A36B2": {Name: "DS-Install-Replica", Type: GUIDTypeExtendedRight, GUID: "9923A32A-3607-11D2-B9BE-0000F87A36B2", Description: "Install a replica of a naming context (promote a domain controller)."},
	"BAE50096-4752-11D1-9052-00C04FC2D4CF": {Name: "Generate-RSoP-Logging", Type: GUIDTypeExtendedRight, GUID: "BAE50096-4752-11D1-9052-00C04FC2D4CF", Description: "Generate Resultant Set of Policy logging data."},
	"B7B1B3DD-AB09-4242-9E30-9980E5D322F7": {Name: "Generate-RSoP-Planning", Type: GUIDTypeExtendedRight, GUID: "B7B1B3DD-AB09-4242-9E30-9980E5D322F7", Description: "Generate Resultant Set of Policy planning data."},
	"FEC364E0-0A98-11D1-ADBB-00C04FD8D5CD": {Name: "Abandon-Replication", Type: GUIDTypeExtendedRight, GUID: "FEC364E0-0A98-11D1-ADBB-00C04FD8D5CD", Description: "Abandon an in-progress replication operation."},
	"E12B56B6-0A95-11D1-ADBB-00C04FD8D5CD": {Name: "Allocate-Rids", Type: GUIDTypeExtendedRight, GUID: "E12B56B6-0A95-11D1-ADBB-00C04FD8D5CD", Description: "Allocate a pool of RIDs from the RID Master for creating new security principals."},
	"D58D5F36-0A98-11D1-ADBB-00C04FD8D5CD": {Name: "Recalculate-Hierarchy", Type: GUIDTypeExtendedRight, GUID: "D58D5F36-0A98-11D1-ADBB-00C04FD8D5CD", Description: "Recalculate the hierarchy of objects in a naming context."},
	"0BC1554E-0A99-11D1-ADBB-00C04FD8D5CD": {Name: "Refresh-Group-Cache", Type: GUIDTypeExtendedRight, GUID: "0BC1554E-0A99-11D1-ADBB-00C04FD8D5CD", Description: "Refresh the group membership cache on a domain controller."},
	"05C74C5E-4DEB-43B4-BD9F-86664C2A7FD5": {Name: "Enable-Per-User-Reversibly-Encrypted-Password", Type: GUIDTypeExtendedRight, GUID: "05C74C5E-4DEB-43B4-BD9F-86664C2A7FD5", Description: "Enable storing passwords with reversible encryption for a user."},
	"E48D0154-BCF8-11D1-8702-00C04FB96050": {Name: "Public-Information", Type: GUIDTypeExtendedRight, GUID: "E48D0154-BCF8-11D1-8702-00C04FB96050", Description: "Read public information attributes of an object."},
	"037088F8-0AE1-11D2-B422-00A0C968F939": {Name: "RAS-Information", Type: GUIDTypeExtendedRight, GUID: "037088F8-0AE1-11D2-B422-00A0C968F939", Description: "Read/write Remote Access Service dial-in properties."},
	"5805BC62-BDC9-4428-A5E2-856A0F4C185E": {Name: "Terminal-Server-License-Server", Type: GUIDTypeExtendedRight, GUID: "5805BC62-BDC9-4428-A5E2-856A0F4C185E", Description: "Act as a Terminal Server license server."},

	// Group membership related
	"BC0AC240-79A9-11D0-9020-00C04FC2D4CF": {
		Name:        "Membership",
		Type:        GUIDTypeExtendedRight,
		GUID:        "BC0AC240-79A9-11D0-9020-00C04FC2D4CF",
		Description: "Read group membership information.",
		AppliesTo:   []AppliesToEntry{{GUID: "BF967A9C-0DE6-11D0-A285-00AA003049E2", Name: "Group"}},
	},

	// Validated Writes
	"72E39547-7B18-11D1-ADEF-00C04FD8D5CD": {
		Name:        "Validated-DNS-Host-Name",
		Type:        GUIDTypeValidatedWrite,
		GUID:        "72E39547-7B18-11D1-ADEF-00C04FD8D5CD",
		Description: "Write DNS host name after validation. Validated to match computer account.",
		AppliesTo:   []AppliesToEntry{{GUID: "BF967A86-0DE6-11D0-A285-00AA003049E2", Name: "Computer"}},
	},
	// Security: https://attack.mitre.org/techniques/T1558/003/
	"F3A64788-5306-11D1-A9C5-0000F80367C1": {
		Name:        "Validated-SPN",
		Type:        GUIDTypeValidatedWrite,
		GUID:        "F3A64788-5306-11D1-A9C5-0000F80367C1",
		Description: "Write Service Principal Name after validation. Can enable Kerberoasting if misconfigured.",
		AppliesTo:   []AppliesToEntry{{GUID: "BF967A86-0DE6-11D0-A285-00AA003049E2", Name: "Computer"}, {GUID: "BF967ABA-0DE6-11D0-A285-00AA003049E2", Name: "User"}, {GUID: "CE206244-5827-4A86-BA1C-1C0C386C1B64", Name: "ms-DS-Group-Managed-Service-Account"}},
	},
	"BF9679C0-0DE6-11D0-A285-00AA003049E2": {
		Name:        "Self-Membership",
		Type:        GUIDTypeValidatedWrite,
		GUID:        "BF9679C0-0DE6-11D0-A285-00AA003049E2",
		Description: "Add/remove self from group membership. Allows users to add themselves to groups.",
		AppliesTo:   []AppliesToEntry{{GUID: "BF967A9C-0DE6-11D0-A285-00AA003049E2", Name: "Group"}},
	},

	// Property Sets
	"C7407360-20BF-11D0-A768-00AA006E0529": {
		Name:        "Domain-Password",
		Type:        GUIDTypePropertySet,
		GUID:        "C7407360-20BF-11D0-A768-00AA006E0529",
		Description: "Read/write domain password policy attributes (minPwdAge, maxPwdAge, minPwdLength, etc.).",
		AppliesTo:   []AppliesToEntry{{GUID: "19195A5B-6DA0-11D0-AFA3-00C04FD930C9", Name: "Domain-DNS"}, {GUID: "19195A5A-6DA0-11D0-AFA3-00C04FD930C9", Name: "Sam-Domain"}},
	},
	"4C164200-20C0-11D0-A768-00AA006E0529": {
		Name:        "User-Account-Restrictions",
		Type:        GUIDTypePropertySet,
		GUID:        "4C164200-20C0-11D0-A768-00AA006E0529",
		Description: "Read/write user account restriction attributes (userAccountControl, accountExpires, etc.).",
		AppliesTo:   []AppliesToEntry{{GUID: "BF967ABA-0DE6-11D0-A285-00AA003049E2", Name: "User"}, {GUID: "BF967A86-0DE6-11D0-A285-00AA003049E2", Name: "Computer"}},
	},
	"59BA2F42-79A2-11D0-9020-00C04FC2D3CF": {
		Name:        "General-Information",
		Type:        GUIDTypePropertySet,
		GUID:        "59BA2F42-79A2-11D0-9020-00C04FC2D3CF",
		Description: "Read/write general information attributes (displayName, description, etc.).",
	},
	"5F202010-79A5-11D0-9020-00C04FC2D4CF": {
		Name:        "Logon-Information",
		Type:        GUIDTypePropertySet,
		GUID:        "5F202010-79A5-11D0-9020-00C04FC2D4CF",
		Description: "Read/write logon information attributes (logonHours, userWorkstations, etc.).",
		AppliesTo:   []AppliesToEntry{{GUID: "BF967ABA-0DE6-11D0-A285-00AA003049E2", Name: "User"}, {GUID: "BF967A86-0DE6-11D0-A285-00AA003049E2", Name: "Computer"}},
	},
	"E45795B2-9455-11D1-AEBD-0000F80367C1": {Name: "Email-Information", Type: GUIDTypePropertySet, GUID: "E45795B2-9455-11D1-AEBD-0000F80367C1", Description: "Read/write email-related attributes (mail, proxyAddresses, etc.)."},
	"E45795B3-9455-11D1-AEBD-0000F80367C1": {Name: "Web-Information", Type: GUIDTypePropertySet, GUID: "E45795B3-9455-11D1-AEBD-0000F80367C1", Description: "Read/write web-related attributes (wWWHomePage, url, etc.)."},
	"B8119FD0-04F6-4762-AB7A-4986C76B3F9A": {
		Name:        "Personal-Information",
		Type:        GUIDTypePropertySet,
		GUID:        "B8119FD0-04F6-4762-AB7A-4986C76B3F9A",
		Description: "Read/write personal information attributes (homePhone, homeAddress, etc.).",
	},
	"77B5B886-944A-11D1-AEBD-0000F80367C1": {
		Name:        "Private-Information",
		Type:        GUIDTypePropertySet,
		GUID:        "77B5B886-944A-11D1-AEBD-0000F80367C1",
		Description: "Read/write private information attributes. Contains sensitive user data.",
	},
	"91E647DE-D96F-4B70-9557-D63FF4F3CCD8": {Name: "Phone-and-Mail-Options", Type: GUIDTypePropertySet, GUID: "91E647DE-D96F-4B70-9557-D63FF4F3CCD8", Description: "Read/write phone and mail option attributes (telephoneNumber, facsimileTelephoneNumber, etc.)."},

	// Common Schema Classes (schemaIDGUID)
	"BF967A86-0DE6-11D0-A285-00AA003049E2": {Name: "Computer", Type: GUIDTypeClass, GUID: "BF967A86-0DE6-11D0-A285-00AA003049E2", Description: "Computer account object."},
	"BF967A9C-0DE6-11D0-A285-00AA003049E2": {Name: "Group", Type: GUIDTypeClass, GUID: "BF967A9C-0DE6-11D0-A285-00AA003049E2", Description: "Security or distribution group object."},
	"BF967ABA-0DE6-11D0-A285-00AA003049E2": {Name: "User", Type: GUIDTypeClass, GUID: "BF967ABA-0DE6-11D0-A285-00AA003049E2", Description: "User account object."},
	"19195A5B-6DA0-11D0-AFA3-00C04FD930C9": {Name: "Domain-DNS", Type: GUIDTypeClass, GUID: "19195A5B-6DA0-11D0-AFA3-00C04FD930C9", Description: "Domain DNS zone object (domain root)."},
	"BF967A8B-0DE6-11D0-A285-00AA003049E2": {Name: "Contact", Type: GUIDTypeClass, GUID: "BF967A8B-0DE6-11D0-A285-00AA003049E2", Description: "Contact object (no security principal)."},
	"BF967AA5-0DE6-11D0-A285-00AA003049E2": {Name: "Organizational-Unit", Type: GUIDTypeClass, GUID: "BF967AA5-0DE6-11D0-A285-00AA003049E2", Description: "Organizational Unit (OU) container."},
	"BF967A87-0DE6-11D0-A285-00AA003049E2": {Name: "Container", Type: GUIDTypeClass, GUID: "BF967A87-0DE6-11D0-A285-00AA003049E2", Description: "Generic container object."},
	"5CB41ED0-0E4C-11D0-A286-00AA003049E2": {Name: "Group-Policy-Container", Type: GUIDTypeClass, GUID: "5CB41ED0-0E4C-11D0-A286-00AA003049E2", Description: "Group Policy Object (GPO)."},
	"B7B13124-B82E-11D0-AFEE-0000F80367C1": {Name: "Builtin-Domain", Type: GUIDTypeClass, GUID: "B7B13124-B82E-11D0-AFEE-0000F80367C1", Description: "Built-in domain container (CN=Builtin)."},
	"BF967AA0-0DE6-11D0-A285-00AA003049E2": {Name: "Domain-Policy", Type: GUIDTypeClass, GUID: "BF967AA0-0DE6-11D0-A285-00AA003049E2", Description: "Domain policy object."},
	"BF967AB3-0DE6-11D0-A285-00AA003049E2": {Name: "Print-Queue", Type: GUIDTypeClass, GUID: "BF967AB3-0DE6-11D0-A285-00AA003049E2", Description: "Published printer object."},
	"19195A5A-6DA0-11D0-AFA3-00C04FD930C9": {Name: "Sam-Domain", Type: GUIDTypeClass, GUID: "19195A5A-6DA0-11D0-AFA3-00C04FD930C9", Description: "SAM domain object."},
	"BF967AB8-0DE6-11D0-A285-00AA003049E2": {Name: "Service-Connection-Point", Type: GUIDTypeClass, GUID: "BF967AB8-0DE6-11D0-A285-00AA003049E2", Description: "Service connection point for service discovery."},
	"CE206244-5827-4A86-BA1C-1C0C386C1B64": {Name: "ms-DS-Group-Managed-Service-Account", Type: GUIDTypeClass, GUID: "CE206244-5827-4A86-BA1C-1C0C386C1B64", Description: "Group Managed Service Account (gMSA)."},
	"BF967ABB-0DE6-11D0-A285-00AA003049E2": {Name: "Volume", Type: GUIDTypeClass, GUID: "BF967ABB-0DE6-11D0-A285-00AA003049E2", Description: "Published volume object."},
	"F0F8FFAC-1191-11D0-A060-00AA006C33ED": {Name: "Shared-Folder", Type: GUIDTypeClass, GUID: "F0F8FFAC-1191-11D0-A060-00AA006C33ED", Description: "Published shared folder object."},
	"E0FA1E8C-9B45-11D0-AFDD-00C04FD930C9": {Name: "PKI-Certificate-Template", Type: GUIDTypeClass, GUID: "E0FA1E8C-9B45-11D0-AFDD-00C04FD930C9", Description: "Certificate template for AD Certificate Services."},
	"3FDF05A1-9DCD-11D1-A9C5-0000F80367C1": {Name: "Configuration", Type: GUIDTypeClass, GUID: "3FDF05A1-9DCD-11D1-A9C5-0000F80367C1", Description: "Configuration naming context container."},
	"BF967A91-0DE6-11D0-A285-00AA003049E2": {Name: "DMD", Type: GUIDTypeClass, GUID: "BF967A91-0DE6-11D0-A285-00AA003049E2", Description: "Directory Management Domain (schema container)."},

	// Common Attributes
	"BF967953-0DE6-11D0-A285-00AA003049E2": {Name: "displayName", Type: GUIDTypeAttribute, GUID: "BF967953-0DE6-11D0-A285-00AA003049E2", Description: "Display name shown in address book and UI."},
	"BF967950-0DE6-11D0-A285-00AA003049E2": {Name: "description", Type: GUIDTypeAttribute, GUID: "BF967950-0DE6-11D0-A285-00AA003049E2", Description: "Free-text description of the object."},
	"BF96799F-0DE6-11D0-A285-00AA003049E2": {
		Name:        "member",
		Type:        GUIDTypeAttribute,
		GUID:        "BF96799F-0DE6-11D0-A285-00AA003049E2",
		Description: "Group membership attribute. Write access allows adding members to groups.",
	},
	"BF9679A4-0DE6-11D0-A285-00AA003049E2": {
		Name:        "msDS-AllowedToDelegateTo",
		Type:        GUIDTypeAttribute,
		GUID:        "BF9679A4-0DE6-11D0-A285-00AA003049E2",
		Description: "Constrained delegation target SPNs. Write access enables configuring delegation attacks.",
	},
	// Security: https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd
	"3F78C3E5-F79A-46BD-A0B8-9D18116DDC79": {
		Name:        "msDS-AllowedToActOnBehalfOfOtherIdentity",
		Type:        GUIDTypeAttribute,
		GUID:        "3F78C3E5-F79A-46BD-A0B8-9D18116DDC79",
		Description: "Resource-based constrained delegation. Write access enables RBCD attacks for privilege escalation.",
	},
	"BF967A68-0DE6-11D0-A285-00AA003049E2": {
		Name:        "userAccountControl",
		Type:        GUIDTypeAttribute,
		GUID:        "BF967A68-0DE6-11D0-A285-00AA003049E2",
		Description: "User account control flags. Write access can disable Kerberos pre-auth, enable delegation, etc.",
	},
	"BF967A6E-0DE6-11D0-A285-00AA003049E2": {Name: "adminCount", Type: GUIDTypeAttribute, GUID: "BF967A6E-0DE6-11D0-A285-00AA003049E2", Description: "Indicates whether the object is protected by AdminSDHolder."},
	// Security: https://attack.mitre.org/techniques/T1558/003/
	"28630EBB-41D5-11D1-A9C1-0000F80367C1": {
		Name:        "servicePrincipalName",
		Type:        GUIDTypeAttribute,
		GUID:        "28630EBB-41D5-11D1-A9C1-0000F80367C1",
		Description: "Service Principal Name. Write access can enable Kerberoasting attacks.",
	},
	"E0FA1E69-9B45-11D0-AFDD-00C04FD930C9": {Name: "ms-Exch-Owner-BL", Type: GUIDTypeAttribute, GUID: "E0FA1E69-9B45-11D0-AFDD-00C04FD930C9", Description: "Back-link for Exchange mailbox ownership."},
	"DBDEC994-E95D-11D0-B6E3-00C04FD930C9": {
		Name:        "gpLink",
		Type:        GUIDTypeAttribute,
		GUID:        "DBDEC994-E95D-11D0-B6E3-00C04FD930C9",
		Description: "Group Policy link. Write access allows linking GPOs for code execution.",
	},
	"F30E3BBE-9FF0-11D1-B603-0000F80367C1": {Name: "gPOptions", Type: GUIDTypeAttribute, GUID: "F30E3BBE-9FF0-11D1-B603-0000F80367C1", Description: "Group Policy inheritance options (e.g. block inheritance)."},
	// Security: https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab
	"5B47D60F-6090-40B2-9F37-2A4DE88F3063": {
		Name:        "msDS-KeyCredentialLink",
		Type:        GUIDTypeAttribute,
		GUID:        "5B47D60F-6090-40B2-9F37-2A4DE88F3063",
		Description: "Shadow Credentials attribute. Write access enables Shadow Credentials attack for auth as the target.",
	},
}
