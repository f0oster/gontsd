package gontsd

import (
	"fmt"
	"strings"
)

// Well-known SID constants.
// See: https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids
const (
	// Placeholder and filter SIDs
	wellKnownSID_NOBODY               = "S-1-0-0"
	wellKnownSID_EVERYONE             = "S-1-1-0"
	wellKnownSID_LOCAL                = "S-1-2-0"
	wellKnownSID_CONSOLE_LOGON        = "S-1-2-1"
	wellKnownSID_CREATOR_OWNER        = "S-1-3-0"
	wellKnownSID_CREATOR_GROUP        = "S-1-3-1"
	wellKnownSID_CREATOR_OWNER_SERVER = "S-1-3-2"
	wellKnownSID_CREATOR_GROUP_SERVER = "S-1-3-3"

	// Built-In SIDs
	wellKnownSID_BUILTIN_DOMAIN                              = "S-1-5-32"
	wellKnownSID_BUILTIN_ADMINISTRATORS                      = "S-1-5-32-544"
	wellKnownSID_BUILTIN_USERS                               = "S-1-5-32-545"
	wellKnownSID_BUILTIN_GUESTS                              = "S-1-5-32-546"
	wellKnownSID_BUILTIN_POWER_USERS                         = "S-1-5-32-547"
	wellKnownSID_BUILTIN_ACCOUNT_OPERATORS                   = "S-1-5-32-548"
	wellKnownSID_BUILTIN_SERVER_OPERATORS                    = "S-1-5-32-549"
	wellKnownSID_BUILTIN_PRINT_OPERATORS                     = "S-1-5-32-550"
	wellKnownSID_BUILTIN_BACKUP_OPERATORS                    = "S-1-5-32-551"
	wellKnownSID_BUILTIN_REPLICATORS                         = "S-1-5-32-552"
	wellKnownSID_BUILTIN_PRE_WINDOWS_2000_COMPATIBLE_ACCESS  = "S-1-5-32-554"
	wellKnownSID_BUILTIN_REMOTE_DESKTOP_USERS                = "S-1-5-32-555"
	wellKnownSID_BUILTIN_NETWORK_CONFIGURATION_OPERATORS     = "S-1-5-32-556"
	wellKnownSID_BUILTIN_INCOMING_FOREST_TRUST_BUILDERS      = "S-1-5-32-557"
	wellKnownSID_BUILTIN_PERFORMANCE_MONITOR_USERS           = "S-1-5-32-558"
	wellKnownSID_BUILTIN_PERFORMANCE_LOG_USERS               = "S-1-5-32-559"
	wellKnownSID_BUILTIN_WINDOWS_AUTHORIZATION_ACCESS_GROUP  = "S-1-5-32-560"
	wellKnownSID_BUILTIN_TERMINAL_SERVER_LICENSE_SERVERS     = "S-1-5-32-561"
	wellKnownSID_BUILTIN_DISTRIBUTED_COM_USERS               = "S-1-5-32-562"
	wellKnownSID_BUILTIN_CRYPTOGRAPHIC_OPERATORS             = "S-1-5-32-569"
	wellKnownSID_BUILTIN_EVENT_LOG_READERS                   = "S-1-5-32-573"
	wellKnownSID_BUILTIN_CERTIFICATE_SERVICE_DCOM_ACCESS     = "S-1-5-32-574"
	wellKnownSID_BUILTIN_RDS_REMOTE_ACCESS_SERVERS           = "S-1-5-32-575"
	wellKnownSID_BUILTIN_RDS_ENDPOINT_SERVERS                = "S-1-5-32-576"
	wellKnownSID_BUILTIN_RDS_MANAGEMENT_SERVERS              = "S-1-5-32-577"
	wellKnownSID_BUILTIN_HYPER_V_ADMINISTRATORS              = "S-1-5-32-578"
	wellKnownSID_BUILTIN_ACCESS_CONTROL_ASSISTANCE_OPERATORS = "S-1-5-32-579"
	wellKnownSID_BUILTIN_REMOTE_MANAGEMENT_USERS             = "S-1-5-32-580"

	// NTAuthority SIDs
	wellKnownSID_NT_AUTHORITY                               = "S-1-5"
	wellKnownSID_NT_AUTHORITY_DIALUP                        = "S-1-5-1"
	wellKnownSID_NT_AUTHORITY_NETWORK                       = "S-1-5-2"
	wellKnownSID_NT_AUTHORITY_BATCH                         = "S-1-5-3"
	wellKnownSID_NT_AUTHORITY_INTERACTIVE                   = "S-1-5-4"
	wellKnownSID_NT_AUTHORITY_SERVICE                       = "S-1-5-6"
	wellKnownSID_NT_AUTHORITY_ANONYMOUS                     = "S-1-5-7"
	wellKnownSID_NT_AUTHORITY_PROXY                         = "S-1-5-8"
	wellKnownSID_NT_AUTHORITY_ENTERPRISE_DOMAIN_CONTROLLERS = "S-1-5-9"
	wellKnownSID_NT_AUTHORITY_PRINCIPAL_SELF                = "S-1-5-10"
	wellKnownSID_NT_AUTHORITY_AUTHENTICATED_USERS           = "S-1-5-11"
	wellKnownSID_NT_AUTHORITY_RESTRICTED_CODE               = "S-1-5-12"
	wellKnownSID_NT_AUTHORITY_TERMINAL_SERVER_USERS         = "S-1-5-13"
	wellKnownSID_NT_AUTHORITY_REMOTE_INTERACTIVE_LOGON      = "S-1-5-14"
	wellKnownSID_NT_AUTHORITY_THIS_ORGANIZATION             = "S-1-5-15"
	wellKnownSID_NT_AUTHORITY_IUSR                          = "S-1-5-17"
	wellKnownSID_NT_AUTHORITY_LOCAL_SYSTEM                  = "S-1-5-18"
	wellKnownSID_NT_AUTHORITY_LOCAL_SERVICE                 = "S-1-5-19"
	wellKnownSID_NT_AUTHORITY_NETWORK_SERVICE               = "S-1-5-20"
	wellKnownSID_NT_AUTHORITY_NTLM_AUTHENTICATION           = "S-1-5-64-10"
	wellKnownSID_NT_AUTHORITY_SCHANNEL_AUTHENTICATION       = "S-1-5-64-14"
	wellKnownSID_NT_AUTHORITY_DIGEST_AUTHENTICATION         = "S-1-5-64-21"

	// Mandatory Label SIDs
	wellKnownSID_SECURITY_MANDATORY_LABEL_UNTRUSTED_LEVEL             = "S-1-16-0"
	wellKnownSID_SECURITY_MANDATORY_LABEL_LOW_INTEGRITY_LEVEL         = "S-1-16-4096"
	wellKnownSID_SECURITY_MANDATORY_LABEL_MEDIUM_INTEGRITY_LEVEL      = "S-1-16-8192"
	wellKnownSID_SECURITY_MANDATORY_LABEL_MEDIUM_PLUS_INTEGRITY_LEVEL = "S-1-16-8448"
	wellKnownSID_SECURITY_MANDATORY_LABEL_HIGH_INTEGRITY_LEVEL        = "S-1-16-12288"
	wellKnownSID_SECURITY_MANDATORY_LABEL_SYSTEM_INTEGRITY_LEVEL      = "S-1-16-16384"
	wellKnownSID_SECURITY_MANDATORY_LABEL_PROTECTED_PROCESS           = "S-1-16-20480"
	wellKnownSID_SECURITY_MANDATORY_LABEL_SECURE_PROCESS              = "S-1-16-28672"
)

// wellKnownSIDs maps SID strings to human-readable names.
var wellKnownSIDs = map[string]string{
	// Placeholder and filter SIDs
	wellKnownSID_NOBODY:               "Nobody",
	wellKnownSID_EVERYONE:             "Everyone",
	wellKnownSID_LOCAL:                "Local",
	wellKnownSID_CONSOLE_LOGON:        "Console Logon",
	wellKnownSID_CREATOR_OWNER:        "Creator Owner",
	wellKnownSID_CREATOR_GROUP:        "Creator Group",
	wellKnownSID_CREATOR_OWNER_SERVER: "Creator Owner Server",
	wellKnownSID_CREATOR_GROUP_SERVER: "Creator Group Server",

	// Built-In SIDs
	wellKnownSID_BUILTIN_DOMAIN:                              "BUILTIN",
	wellKnownSID_BUILTIN_ADMINISTRATORS:                      "BUILTIN\\Administrators",
	wellKnownSID_BUILTIN_USERS:                               "BUILTIN\\Users",
	wellKnownSID_BUILTIN_GUESTS:                              "BUILTIN\\Guests",
	wellKnownSID_BUILTIN_POWER_USERS:                         "BUILTIN\\Power Users",
	wellKnownSID_BUILTIN_ACCOUNT_OPERATORS:                   "BUILTIN\\Account Operators",
	wellKnownSID_BUILTIN_SERVER_OPERATORS:                    "BUILTIN\\Server Operators",
	wellKnownSID_BUILTIN_PRINT_OPERATORS:                     "BUILTIN\\Print Operators",
	wellKnownSID_BUILTIN_BACKUP_OPERATORS:                    "BUILTIN\\Backup Operators",
	wellKnownSID_BUILTIN_REPLICATORS:                         "BUILTIN\\Replicators",
	wellKnownSID_BUILTIN_PRE_WINDOWS_2000_COMPATIBLE_ACCESS:  "BUILTIN\\Pre-Windows 2000 Compatible Access",
	wellKnownSID_BUILTIN_REMOTE_DESKTOP_USERS:                "BUILTIN\\Remote Desktop Users",
	wellKnownSID_BUILTIN_NETWORK_CONFIGURATION_OPERATORS:     "BUILTIN\\Network Configuration Operators",
	wellKnownSID_BUILTIN_INCOMING_FOREST_TRUST_BUILDERS:      "BUILTIN\\Incoming Forest Trust Builders",
	wellKnownSID_BUILTIN_PERFORMANCE_MONITOR_USERS:           "BUILTIN\\Performance Monitor Users",
	wellKnownSID_BUILTIN_PERFORMANCE_LOG_USERS:               "BUILTIN\\Performance Log Users",
	wellKnownSID_BUILTIN_WINDOWS_AUTHORIZATION_ACCESS_GROUP:  "BUILTIN\\Windows Authorization Access Group",
	wellKnownSID_BUILTIN_TERMINAL_SERVER_LICENSE_SERVERS:     "BUILTIN\\Terminal Server License Servers",
	wellKnownSID_BUILTIN_DISTRIBUTED_COM_USERS:               "BUILTIN\\Distributed COM Users",
	wellKnownSID_BUILTIN_CRYPTOGRAPHIC_OPERATORS:             "BUILTIN\\Cryptographic Operators",
	wellKnownSID_BUILTIN_EVENT_LOG_READERS:                   "BUILTIN\\Event Log Readers",
	wellKnownSID_BUILTIN_CERTIFICATE_SERVICE_DCOM_ACCESS:     "BUILTIN\\Certificate Service DCOM Access",
	wellKnownSID_BUILTIN_RDS_REMOTE_ACCESS_SERVERS:           "BUILTIN\\RDS Remote Access Servers",
	wellKnownSID_BUILTIN_RDS_ENDPOINT_SERVERS:                "BUILTIN\\RDS Endpoint Servers",
	wellKnownSID_BUILTIN_RDS_MANAGEMENT_SERVERS:              "BUILTIN\\RDS Management Servers",
	wellKnownSID_BUILTIN_HYPER_V_ADMINISTRATORS:              "BUILTIN\\Hyper-V Administrators",
	wellKnownSID_BUILTIN_ACCESS_CONTROL_ASSISTANCE_OPERATORS: "BUILTIN\\Access Control Assistance Operators",
	wellKnownSID_BUILTIN_REMOTE_MANAGEMENT_USERS:             "BUILTIN\\Remote Management Users",

	// NT\Authority
	wellKnownSID_NT_AUTHORITY:                               "NT Authority",
	wellKnownSID_NT_AUTHORITY_DIALUP:                        "Dialup",
	wellKnownSID_NT_AUTHORITY_NETWORK:                       "Network",
	wellKnownSID_NT_AUTHORITY_BATCH:                         "Batch",
	wellKnownSID_NT_AUTHORITY_INTERACTIVE:                   "Interactive",
	wellKnownSID_NT_AUTHORITY_SERVICE:                       "Service",
	wellKnownSID_NT_AUTHORITY_ANONYMOUS:                     "Anonymous",
	wellKnownSID_NT_AUTHORITY_PROXY:                         "Proxy",
	wellKnownSID_NT_AUTHORITY_ENTERPRISE_DOMAIN_CONTROLLERS: "Enterprise Domain Controllers",
	wellKnownSID_NT_AUTHORITY_PRINCIPAL_SELF:                "Principal Self",
	wellKnownSID_NT_AUTHORITY_AUTHENTICATED_USERS:           "Authenticated Users",
	wellKnownSID_NT_AUTHORITY_RESTRICTED_CODE:               "Restricted Code",
	wellKnownSID_NT_AUTHORITY_TERMINAL_SERVER_USERS:         "Terminal Server Users",
	wellKnownSID_NT_AUTHORITY_REMOTE_INTERACTIVE_LOGON:      "Remote Interactive Logon",
	wellKnownSID_NT_AUTHORITY_THIS_ORGANIZATION:             "This Organization",
	wellKnownSID_NT_AUTHORITY_IUSR:                          "IUSR",
	wellKnownSID_NT_AUTHORITY_LOCAL_SYSTEM:                  "Local System",
	wellKnownSID_NT_AUTHORITY_LOCAL_SERVICE:                 "Local Service",
	wellKnownSID_NT_AUTHORITY_NETWORK_SERVICE:               "Network Service",
	wellKnownSID_NT_AUTHORITY_NTLM_AUTHENTICATION:           "NTLM Authentication",
	wellKnownSID_NT_AUTHORITY_SCHANNEL_AUTHENTICATION:       "SChannel Authentication",
	wellKnownSID_NT_AUTHORITY_DIGEST_AUTHENTICATION:         "Digest Authentication",

	// Mandatory integrity levels
	wellKnownSID_SECURITY_MANDATORY_LABEL_UNTRUSTED_LEVEL:             "Untrusted Level",
	wellKnownSID_SECURITY_MANDATORY_LABEL_LOW_INTEGRITY_LEVEL:         "Low Integrity Level",
	wellKnownSID_SECURITY_MANDATORY_LABEL_MEDIUM_INTEGRITY_LEVEL:      "Medium Integrity Level",
	wellKnownSID_SECURITY_MANDATORY_LABEL_MEDIUM_PLUS_INTEGRITY_LEVEL: "Medium Plus Integrity Level",
	wellKnownSID_SECURITY_MANDATORY_LABEL_HIGH_INTEGRITY_LEVEL:        "High Integrity Level",
	wellKnownSID_SECURITY_MANDATORY_LABEL_SYSTEM_INTEGRITY_LEVEL:      "System Integrity Level",
	wellKnownSID_SECURITY_MANDATORY_LABEL_PROTECTED_PROCESS:           "Protected Process",
	wellKnownSID_SECURITY_MANDATORY_LABEL_SECURE_PROCESS:              "Secure Process",
}

// domainRelativeRIDs maps well-known RIDs to names for domain SIDs (S-1-5-21-*).
// See: https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids
var domainRelativeRIDs = map[string]string{
	"500": "Administrator",
	"501": "Guest",
	"502": "KRBTGT",
	"512": "Domain Admins",
	"513": "Domain Users",
	"514": "Domain Guests",
	"515": "Domain Computers",
	"516": "Domain Controllers",
	"517": "Cert Publishers",
	"518": "Schema Admins",
	"519": "Enterprise Admins",
	"520": "Group Policy Creator Owners",
	"521": "Read-Only Domain Controllers",
	"522": "Cloneable Domain Controllers",
	"553": "RAS Servers",
}

// SIDResolver resolves SIDs to human-readable names.
// to try multiple resolvers in order.
type SIDResolver interface {
	Resolve(sid *SID) (name string, err error)
}

// wellKnownSIDResolver resolves SIDs using the built-in wellKnownSIDs table
// and domain-relative RID matching for S-1-5-21-* SIDs.
type wellKnownSIDResolver struct{}

func (wellKnownSIDResolver) Resolve(sid *SID) (string, error) {
	if sid == nil {
		return "", fmt.Errorf("nil SID")
	}
	if name, ok := wellKnownSIDs[sid.Value]; ok {
		return name, nil
	}
	if strings.HasPrefix(sid.Value, "S-1-5-21-") {
		if i := strings.LastIndex(sid.Value, "-"); i >= 0 {
			rid := sid.Value[i+1:]
			if name, ok := domainRelativeRIDs[rid]; ok {
				return name, nil
			}
		}
	}
	return "", fmt.Errorf("unknown SID: %s", sid.Value)
}

// chainSIDResolver tries multiple resolvers in order until one succeeds.
type chainSIDResolver struct {
	Resolvers []SIDResolver
}

func (c chainSIDResolver) Resolve(sid *SID) (string, error) {
	for _, r := range c.Resolvers {
		if name, err := r.Resolve(sid); err == nil {
			return name, nil
		}
	}
	return "", fmt.Errorf("no resolver could resolve SID: %s", sid.Value)
}

// sidResult holds the outcome of resolving a single SID.
type sidResult struct {
	Name string
	Err  error
}

// batchSIDResolver is an optional interface for resolvers that support
// resolving multiple SIDs in fewer round-trips than individual calls.
type batchSIDResolver interface {
	ResolveBatch(sids []*SID) map[string]sidResult
}

// resolveBatchSIDs resolves multiple SIDs using the given resolver.
// If the resolver (or any resolver in a chain) implements [batchSIDResolver],
// SIDs are resolved in bulk LDAP queries. Otherwise it falls back to
// individual Resolve calls. Results are keyed by SID string.
func resolveBatchSIDs(resolver SIDResolver, sids []*SID) map[string]sidResult {
	if br, ok := findBatchResolver(resolver); ok {
		return br.ResolveBatch(sids)
	}

	results := make(map[string]sidResult, len(sids))
	for _, sid := range sids {
		if sid == nil {
			continue
		}
		name, err := resolver.Resolve(sid)
		results[sid.Value] = sidResult{Name: name, Err: err}
	}
	return results
}

// formatSID resolves a SID using the given resolver and returns a
// display string like "Local System (S-1-5-18)". If the SID cannot
// be resolved, it returns the raw SID string.
func formatSID(sid *SID, resolver SIDResolver) string {
	if sid == nil {
		return "<nil>"
	}
	name, err := resolver.Resolve(sid)
	if err != nil {
		return sid.Value
	}
	return fmt.Sprintf("%s (%s)", name, sid.Value)
}

func findBatchResolver(r SIDResolver) (batchSIDResolver, bool) {
	if br, ok := r.(batchSIDResolver); ok {
		return br, true
	}
	if chain, ok := r.(chainSIDResolver); ok {
		for _, inner := range chain.Resolvers {
			if br, found := findBatchResolver(inner); found {
				return br, true
			}
		}
	}
	return nil, false
}
