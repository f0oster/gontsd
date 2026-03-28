package resolve

import (
	"fmt"
	"strings"

	"github.com/f0oster/gontsd"
)

// Well-known SID constants.
// See: https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids
const (
	// Placeholder and filter SIDs
	WELLKNOWNSID_NOBODY               = "S-1-0-0"
	WELLKNOWNSID_EVERYONE             = "S-1-1-0"
	WELLKNOWNSID_LOCAL                = "S-1-2-0"
	WELLKNOWNSID_CONSOLE_LOGON        = "S-1-2-1"
	WELLKNOWNSID_CREATOR_OWNER        = "S-1-3-0"
	WELLKNOWNSID_CREATOR_GROUP        = "S-1-3-1"
	WELLKNOWNSID_CREATOR_OWNER_SERVER = "S-1-3-2"
	WELLKNOWNSID_CREATOR_GROUP_SERVER = "S-1-3-3"

	// Built-In SIDs
	WELLKNOWNSID_BUILTIN_DOMAIN                              = "S-1-5-32"
	WELLKNOWNSID_BUILTIN_ADMINISTRATORS                      = "S-1-5-32-544"
	WELLKNOWNSID_BUILTIN_USERS                               = "S-1-5-32-545"
	WELLKNOWNSID_BUILTIN_GUESTS                              = "S-1-5-32-546"
	WELLKNOWNSID_BUILTIN_POWER_USERS                         = "S-1-5-32-547"
	WELLKNOWNSID_BUILTIN_ACCOUNT_OPERATORS                   = "S-1-5-32-548"
	WELLKNOWNSID_BUILTIN_SERVER_OPERATORS                    = "S-1-5-32-549"
	WELLKNOWNSID_BUILTIN_PRINT_OPERATORS                     = "S-1-5-32-550"
	WELLKNOWNSID_BUILTIN_BACKUP_OPERATORS                    = "S-1-5-32-551"
	WELLKNOWNSID_BUILTIN_REPLICATORS                         = "S-1-5-32-552"
	WELLKNOWNSID_BUILTIN_PRE_WINDOWS_2000_COMPATIBLE_ACCESS  = "S-1-5-32-554"
	WELLKNOWNSID_BUILTIN_REMOTE_DESKTOP_USERS                = "S-1-5-32-555"
	WELLKNOWNSID_BUILTIN_NETWORK_CONFIGURATION_OPERATORS     = "S-1-5-32-556"
	WELLKNOWNSID_BUILTIN_INCOMING_FOREST_TRUST_BUILDERS      = "S-1-5-32-557"
	WELLKNOWNSID_BUILTIN_PERFORMANCE_MONITOR_USERS           = "S-1-5-32-558"
	WELLKNOWNSID_BUILTIN_PERFORMANCE_LOG_USERS               = "S-1-5-32-559"
	WELLKNOWNSID_BUILTIN_WINDOWS_AUTHORIZATION_ACCESS_GROUP  = "S-1-5-32-560"
	WELLKNOWNSID_BUILTIN_TERMINAL_SERVER_LICENSE_SERVERS     = "S-1-5-32-561"
	WELLKNOWNSID_BUILTIN_DISTRIBUTED_COM_USERS               = "S-1-5-32-562"
	WELLKNOWNSID_BUILTIN_CRYPTOGRAPHIC_OPERATORS             = "S-1-5-32-569"
	WELLKNOWNSID_BUILTIN_EVENT_LOG_READERS                   = "S-1-5-32-573"
	WELLKNOWNSID_BUILTIN_CERTIFICATE_SERVICE_DCOM_ACCESS     = "S-1-5-32-574"
	WELLKNOWNSID_BUILTIN_RDS_REMOTE_ACCESS_SERVERS           = "S-1-5-32-575"
	WELLKNOWNSID_BUILTIN_RDS_ENDPOINT_SERVERS                = "S-1-5-32-576"
	WELLKNOWNSID_BUILTIN_RDS_MANAGEMENT_SERVERS              = "S-1-5-32-577"
	WELLKNOWNSID_BUILTIN_HYPER_V_ADMINISTRATORS              = "S-1-5-32-578"
	WELLKNOWNSID_BUILTIN_ACCESS_CONTROL_ASSISTANCE_OPERATORS = "S-1-5-32-579"
	WELLKNOWNSID_BUILTIN_REMOTE_MANAGEMENT_USERS             = "S-1-5-32-580"

	// NTAuthority SIDs
	WELLKNOWNSID_NT_AUTHORITY                               = "S-1-5"
	WELLKNOWNSID_NT_AUTHORITY_DIALUP                        = "S-1-5-1"
	WELLKNOWNSID_NT_AUTHORITY_NETWORK                       = "S-1-5-2"
	WELLKNOWNSID_NT_AUTHORITY_BATCH                         = "S-1-5-3"
	WELLKNOWNSID_NT_AUTHORITY_INTERACTIVE                   = "S-1-5-4"
	WELLKNOWNSID_NT_AUTHORITY_SERVICE                       = "S-1-5-6"
	WELLKNOWNSID_NT_AUTHORITY_ANONYMOUS                     = "S-1-5-7"
	WELLKNOWNSID_NT_AUTHORITY_PROXY                         = "S-1-5-8"
	WELLKNOWNSID_NT_AUTHORITY_ENTERPRISE_DOMAIN_CONTROLLERS = "S-1-5-9"
	WELLKNOWNSID_NT_AUTHORITY_PRINCIPAL_SELF                = "S-1-5-10"
	WELLKNOWNSID_NT_AUTHORITY_AUTHENTICATED_USERS           = "S-1-5-11"
	WELLKNOWNSID_NT_AUTHORITY_RESTRICTED_CODE               = "S-1-5-12"
	WELLKNOWNSID_NT_AUTHORITY_TERMINAL_SERVER_USERS         = "S-1-5-13"
	WELLKNOWNSID_NT_AUTHORITY_REMOTE_INTERACTIVE_LOGON      = "S-1-5-14"
	WELLKNOWNSID_NT_AUTHORITY_THIS_ORGANIZATION             = "S-1-5-15"
	WELLKNOWNSID_NT_AUTHORITY_IUSR                          = "S-1-5-17"
	WELLKNOWNSID_NT_AUTHORITY_LOCAL_SYSTEM                  = "S-1-5-18"
	WELLKNOWNSID_NT_AUTHORITY_LOCAL_SERVICE                 = "S-1-5-19"
	WELLKNOWNSID_NT_AUTHORITY_NETWORK_SERVICE               = "S-1-5-20"
	WELLKNOWNSID_NT_AUTHORITY_NTLM_AUTHENTICATION           = "S-1-5-64-10"
	WELLKNOWNSID_NT_AUTHORITY_SCHANNEL_AUTHENTICATION       = "S-1-5-64-14"
	WELLKNOWNSID_NT_AUTHORITY_DIGEST_AUTHENTICATION         = "S-1-5-64-21"

	// Mandatory Label SIDs
	WELLKNOWNSID_SECURITY_MANDATORY_LABEL_UNTRUSTED_LEVEL             = "S-1-16-0"
	WELLKNOWNSID_SECURITY_MANDATORY_LABEL_LOW_INTEGRITY_LEVEL         = "S-1-16-4096"
	WELLKNOWNSID_SECURITY_MANDATORY_LABEL_MEDIUM_INTEGRITY_LEVEL      = "S-1-16-8192"
	WELLKNOWNSID_SECURITY_MANDATORY_LABEL_MEDIUM_PLUS_INTEGRITY_LEVEL = "S-1-16-8448"
	WELLKNOWNSID_SECURITY_MANDATORY_LABEL_HIGH_INTEGRITY_LEVEL        = "S-1-16-12288"
	WELLKNOWNSID_SECURITY_MANDATORY_LABEL_SYSTEM_INTEGRITY_LEVEL      = "S-1-16-16384"
	WELLKNOWNSID_SECURITY_MANDATORY_LABEL_PROTECTED_PROCESS           = "S-1-16-20480"
	WELLKNOWNSID_SECURITY_MANDATORY_LABEL_SECURE_PROCESS              = "S-1-16-28672"
)

// WellKnownSIDs maps SID strings to human-readable names.
var WellKnownSIDs = map[string]string{
	// Placeholder and filter SIDs
	WELLKNOWNSID_NOBODY:               "Nobody",
	WELLKNOWNSID_EVERYONE:             "Everyone",
	WELLKNOWNSID_LOCAL:                "Local",
	WELLKNOWNSID_CONSOLE_LOGON:        "Console Logon",
	WELLKNOWNSID_CREATOR_OWNER:        "Creator Owner",
	WELLKNOWNSID_CREATOR_GROUP:        "Creator Group",
	WELLKNOWNSID_CREATOR_OWNER_SERVER: "Creator Owner Server",
	WELLKNOWNSID_CREATOR_GROUP_SERVER: "Creator Group Server",

	// Built-In SIDs
	WELLKNOWNSID_BUILTIN_DOMAIN:                              "BUILTIN",
	WELLKNOWNSID_BUILTIN_ADMINISTRATORS:                      "BUILTIN\\Administrators",
	WELLKNOWNSID_BUILTIN_USERS:                               "BUILTIN\\Users",
	WELLKNOWNSID_BUILTIN_GUESTS:                              "BUILTIN\\Guests",
	WELLKNOWNSID_BUILTIN_POWER_USERS:                         "BUILTIN\\Power Users",
	WELLKNOWNSID_BUILTIN_ACCOUNT_OPERATORS:                   "BUILTIN\\Account Operators",
	WELLKNOWNSID_BUILTIN_SERVER_OPERATORS:                    "BUILTIN\\Server Operators",
	WELLKNOWNSID_BUILTIN_PRINT_OPERATORS:                     "BUILTIN\\Print Operators",
	WELLKNOWNSID_BUILTIN_BACKUP_OPERATORS:                    "BUILTIN\\Backup Operators",
	WELLKNOWNSID_BUILTIN_REPLICATORS:                         "BUILTIN\\Replicators",
	WELLKNOWNSID_BUILTIN_PRE_WINDOWS_2000_COMPATIBLE_ACCESS:  "BUILTIN\\Pre-Windows 2000 Compatible Access",
	WELLKNOWNSID_BUILTIN_REMOTE_DESKTOP_USERS:                "BUILTIN\\Remote Desktop Users",
	WELLKNOWNSID_BUILTIN_NETWORK_CONFIGURATION_OPERATORS:     "BUILTIN\\Network Configuration Operators",
	WELLKNOWNSID_BUILTIN_INCOMING_FOREST_TRUST_BUILDERS:      "BUILTIN\\Incoming Forest Trust Builders",
	WELLKNOWNSID_BUILTIN_PERFORMANCE_MONITOR_USERS:           "BUILTIN\\Performance Monitor Users",
	WELLKNOWNSID_BUILTIN_PERFORMANCE_LOG_USERS:               "BUILTIN\\Performance Log Users",
	WELLKNOWNSID_BUILTIN_WINDOWS_AUTHORIZATION_ACCESS_GROUP:  "BUILTIN\\Windows Authorization Access Group",
	WELLKNOWNSID_BUILTIN_TERMINAL_SERVER_LICENSE_SERVERS:     "BUILTIN\\Terminal Server License Servers",
	WELLKNOWNSID_BUILTIN_DISTRIBUTED_COM_USERS:               "BUILTIN\\Distributed COM Users",
	WELLKNOWNSID_BUILTIN_CRYPTOGRAPHIC_OPERATORS:             "BUILTIN\\Cryptographic Operators",
	WELLKNOWNSID_BUILTIN_EVENT_LOG_READERS:                   "BUILTIN\\Event Log Readers",
	WELLKNOWNSID_BUILTIN_CERTIFICATE_SERVICE_DCOM_ACCESS:     "BUILTIN\\Certificate Service DCOM Access",
	WELLKNOWNSID_BUILTIN_RDS_REMOTE_ACCESS_SERVERS:           "BUILTIN\\RDS Remote Access Servers",
	WELLKNOWNSID_BUILTIN_RDS_ENDPOINT_SERVERS:                "BUILTIN\\RDS Endpoint Servers",
	WELLKNOWNSID_BUILTIN_RDS_MANAGEMENT_SERVERS:              "BUILTIN\\RDS Management Servers",
	WELLKNOWNSID_BUILTIN_HYPER_V_ADMINISTRATORS:              "BUILTIN\\Hyper-V Administrators",
	WELLKNOWNSID_BUILTIN_ACCESS_CONTROL_ASSISTANCE_OPERATORS: "BUILTIN\\Access Control Assistance Operators",
	WELLKNOWNSID_BUILTIN_REMOTE_MANAGEMENT_USERS:             "BUILTIN\\Remote Management Users",

	// NT\Authority
	WELLKNOWNSID_NT_AUTHORITY:                               "NT Authority",
	WELLKNOWNSID_NT_AUTHORITY_DIALUP:                        "Dialup",
	WELLKNOWNSID_NT_AUTHORITY_NETWORK:                       "Network",
	WELLKNOWNSID_NT_AUTHORITY_BATCH:                         "Batch",
	WELLKNOWNSID_NT_AUTHORITY_INTERACTIVE:                   "Interactive",
	WELLKNOWNSID_NT_AUTHORITY_SERVICE:                       "Service",
	WELLKNOWNSID_NT_AUTHORITY_ANONYMOUS:                     "Anonymous",
	WELLKNOWNSID_NT_AUTHORITY_PROXY:                         "Proxy",
	WELLKNOWNSID_NT_AUTHORITY_ENTERPRISE_DOMAIN_CONTROLLERS: "Enterprise Domain Controllers",
	WELLKNOWNSID_NT_AUTHORITY_PRINCIPAL_SELF:                "Principal Self",
	WELLKNOWNSID_NT_AUTHORITY_AUTHENTICATED_USERS:           "Authenticated Users",
	WELLKNOWNSID_NT_AUTHORITY_RESTRICTED_CODE:               "Restricted Code",
	WELLKNOWNSID_NT_AUTHORITY_TERMINAL_SERVER_USERS:         "Terminal Server Users",
	WELLKNOWNSID_NT_AUTHORITY_REMOTE_INTERACTIVE_LOGON:      "Remote Interactive Logon",
	WELLKNOWNSID_NT_AUTHORITY_THIS_ORGANIZATION:             "This Organization",
	WELLKNOWNSID_NT_AUTHORITY_IUSR:                          "IUSR",
	WELLKNOWNSID_NT_AUTHORITY_LOCAL_SYSTEM:                  "Local System",
	WELLKNOWNSID_NT_AUTHORITY_LOCAL_SERVICE:                 "Local Service",
	WELLKNOWNSID_NT_AUTHORITY_NETWORK_SERVICE:               "Network Service",
	WELLKNOWNSID_NT_AUTHORITY_NTLM_AUTHENTICATION:           "NTLM Authentication",
	WELLKNOWNSID_NT_AUTHORITY_SCHANNEL_AUTHENTICATION:       "SChannel Authentication",
	WELLKNOWNSID_NT_AUTHORITY_DIGEST_AUTHENTICATION:         "Digest Authentication",

	// Mandatory integrity levels
	WELLKNOWNSID_SECURITY_MANDATORY_LABEL_UNTRUSTED_LEVEL:             "Untrusted Level",
	WELLKNOWNSID_SECURITY_MANDATORY_LABEL_LOW_INTEGRITY_LEVEL:         "Low Integrity Level",
	WELLKNOWNSID_SECURITY_MANDATORY_LABEL_MEDIUM_INTEGRITY_LEVEL:      "Medium Integrity Level",
	WELLKNOWNSID_SECURITY_MANDATORY_LABEL_MEDIUM_PLUS_INTEGRITY_LEVEL: "Medium Plus Integrity Level",
	WELLKNOWNSID_SECURITY_MANDATORY_LABEL_HIGH_INTEGRITY_LEVEL:        "High Integrity Level",
	WELLKNOWNSID_SECURITY_MANDATORY_LABEL_SYSTEM_INTEGRITY_LEVEL:      "System Integrity Level",
	WELLKNOWNSID_SECURITY_MANDATORY_LABEL_PROTECTED_PROCESS:           "Protected Process",
	WELLKNOWNSID_SECURITY_MANDATORY_LABEL_SECURE_PROCESS:              "Secure Process",
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
type SIDResolver interface {
	Resolve(sid *gontsd.SID) (name string, err error)
}

// WellKnownSIDResolver resolves SIDs using the built-in WellKnownSIDs table
// and domain-relative RID matching for S-1-5-21-* SIDs.
type WellKnownSIDResolver struct{}

func (WellKnownSIDResolver) Resolve(sid *gontsd.SID) (string, error) {
	if sid == nil {
		return "", fmt.Errorf("nil SID")
	}
	if name, ok := WellKnownSIDs[sid.Parsed]; ok {
		return name, nil
	}
	if strings.HasPrefix(sid.Parsed, "S-1-5-21-") {
		if i := strings.LastIndex(sid.Parsed, "-"); i >= 0 {
			rid := sid.Parsed[i+1:]
			if name, ok := domainRelativeRIDs[rid]; ok {
				return name, nil
			}
		}
	}
	return "", fmt.Errorf("unknown SID: %s", sid.Parsed)
}

// ChainSIDResolver tries multiple resolvers in order until one succeeds.
type ChainSIDResolver struct {
	Resolvers []SIDResolver
}

func (c ChainSIDResolver) Resolve(sid *gontsd.SID) (string, error) {
	for _, r := range c.Resolvers {
		if name, err := r.Resolve(sid); err == nil {
			return name, nil
		}
	}
	return "", fmt.Errorf("no resolver could resolve SID: %s", sid.Parsed)
}

// BatchSIDResolver is an optional interface for resolvers that support
// resolving multiple SIDs in fewer round-trips than individual calls.
type BatchSIDResolver interface {
	ResolveBatch(sids []*gontsd.SID) map[string]SIDResult
}

// ResolveBatchSIDs resolves multiple SIDs using the given resolver.
// If the resolver (or any resolver in a chain) supports batching,
// it will be used. Otherwise falls back to individual Resolve calls.
func ResolveBatchSIDs(resolver SIDResolver, sids []*gontsd.SID) map[string]SIDResult {
	if br, ok := findBatchResolver(resolver); ok {
		return br.ResolveBatch(sids)
	}

	results := make(map[string]SIDResult, len(sids))
	for _, sid := range sids {
		if sid == nil {
			continue
		}
		name, err := resolver.Resolve(sid)
		results[sid.Parsed] = SIDResult{Name: name, Err: err}
	}
	return results
}

func findBatchResolver(r SIDResolver) (BatchSIDResolver, bool) {
	if br, ok := r.(BatchSIDResolver); ok {
		return br, true
	}
	if chain, ok := r.(ChainSIDResolver); ok {
		for _, inner := range chain.Resolvers {
			if br, found := findBatchResolver(inner); found {
				return br, true
			}
		}
	}
	return nil, false
}
