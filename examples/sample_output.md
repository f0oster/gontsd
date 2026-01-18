# Example Output

This shows sample output from running the examples with LDAP resolution enabled against an Active Directory domain. It demonstrates:

- **SID Resolution**: Well-known SIDs and LDAP-resolved accounts with distinguished names
- **Schema GUID Resolution**: Extended rights, property sets, and attributes with security-relevant descriptions
- **ACE Diff Detection**: Identifying added, removed, modified, and reordered ACEs between security descriptors
- **Security Descriptor Dumps**: Full DACL enumeration with resolved principals and permissions

```bash
go run ./ --ldap-server "ldaps://ws22dcprd01.dom1.f0oster.com:636" --ldap-basedn "DC=dom1,DC=f0oster,DC=com" --ldap-binddn "username" --ldap-password "password"
```

## Output

```
LDAP GUID resolver configured (cached 80 extended rights)

=== Test Case Comparisons ===

=== Test Case: Added Principal To ACE ===

DACL Changes:
  [↔] Reordered to position 1:
      AccessAllowedACE:
        SID:   S-1-5-18 (Local System)
        Mask:  0x001F01FF
        Flags: [RIGHT_DS_CREATE_CHILD RIGHT_DS_DELETE_CHILD RIGHT_DS_WRITE_PROPERTY_EXTENDED RIGHT_DS_LIST_CONTENTS RIGHT_DS_CONTROL_ACCESS RIGHT_WRITE_OWNER RIGHT_DS_DELETE_TREE RIGHT_DELETE RIGHT_DS_READ_PROPERTY RIGHT_DS_WRITE_PROPERTY RIGHT_DS_LIST_OBJECT RIGHT_READ_CONTROL RIGHT_WRITE_DAC]
  [↔] Reordered to position 2:
      AccessAllowedACE:
        SID:   S-1-5-32-544 (BUILTIN\Administrators)
        Mask:  0x001F01FF
        Flags: [RIGHT_DS_DELETE_CHILD RIGHT_DS_READ_PROPERTY RIGHT_DS_WRITE_PROPERTY RIGHT_DELETE RIGHT_DS_CREATE_CHILD RIGHT_DS_WRITE_PROPERTY_EXTENDED RIGHT_DS_LIST_OBJECT RIGHT_READ_CONTROL RIGHT_DS_CONTROL_ACCESS RIGHT_DS_LIST_CONTENTS RIGHT_DS_DELETE_TREE RIGHT_WRITE_DAC RIGHT_WRITE_OWNER]
  [↔] Reordered to position 3:
      AccessAllowedACE:
        SID:   S-1-5-32-545 (BUILTIN\Users)
        Mask:  0x001200A9
        Flags: [RIGHT_DS_LIST_OBJECT RIGHT_READ_CONTROL RIGHT_DS_CREATE_CHILD RIGHT_DS_WRITE_PROPERTY RIGHT_DS_WRITE_PROPERTY_EXTENDED]
  [↔] Reordered to position 4:
      AccessAllowedACE:
        SID:   S-1-5-21-75115020-4145467708-3593911600-1612 (t0-f0oster (CN=t0-f0oster,OU=Admins,OU=Identities,OU=Tier0,DC=dom1,DC=f0oster,DC=com))
        Mask:  0x001F01FF
        Flags: [RIGHT_DS_LIST_OBJECT RIGHT_WRITE_DAC RIGHT_DS_WRITE_PROPERTY RIGHT_DS_CONTROL_ACCESS RIGHT_DELETE RIGHT_WRITE_OWNER RIGHT_DS_LIST_CONTENTS RIGHT_DS_WRITE_PROPERTY_EXTENDED RIGHT_DS_READ_PROPERTY RIGHT_DS_DELETE_TREE RIGHT_READ_CONTROL RIGHT_DS_CREATE_CHILD RIGHT_DS_DELETE_CHILD]
  [+] Added at position 0:
      AccessAllowedACE:
        SID:   S-1-5-21-75115020-4145467708-3593911600-1627 (t2-f0oster (CN=t2-f0oster,OU=Staff,OU=Accounts,DC=dom1,DC=f0oster,DC=com))
        Mask:  0x001301BF
        Flags: [RIGHT_DS_LIST_OBJECT RIGHT_DELETE RIGHT_DS_DELETE_CHILD RIGHT_DS_CONTROL_ACCESS RIGHT_DS_CREATE_CHILD RIGHT_DS_LIST_CONTENTS RIGHT_DS_WRITE_PROPERTY RIGHT_READ_CONTROL RIGHT_DS_WRITE_PROPERTY_EXTENDED RIGHT_DS_READ_PROPERTY]       

=== Test Case: Removed Flag From ACE ===

DACL Changes:
  [~] Modified at position 0:
      AccessAllowedACE:
        SID:  S-1-5-21-75115020-4145467708-3593911600-1627 (t2-f0oster (CN=t2-f0oster,OU=Staff,OU=Accounts,DC=dom1,DC=f0oster,DC=com))
        Mask: 0x001301BF -> 0x001200A9
        RemovedFlags:   [RIGHT_DS_DELETE_CHILD RIGHT_DS_LIST_CONTENTS RIGHT_DS_READ_PROPERTY RIGHT_DELETE RIGHT_DS_CONTROL_ACCESS]
        UnchangedFlags: [RIGHT_DS_CREATE_CHILD RIGHT_DS_WRITE_PROPERTY RIGHT_DS_WRITE_PROPERTY_EXTENDED RIGHT_DS_LIST_OBJECT RIGHT_READ_CONTROL]

=== Test Case: Added Flag To ACE ===

DACL Changes:
  [~] Modified at position 0:
      AccessAllowedACE:
        SID:  S-1-5-21-75115020-4145467708-3593911600-1627 (t2-f0oster (CN=t2-f0oster,OU=Staff,OU=Accounts,DC=dom1,DC=f0oster,DC=com))
        Mask: 0x001200A9 -> 0x001301BF
        AddedFlags:     [RIGHT_DELETE RIGHT_DS_LIST_CONTENTS RIGHT_DS_CONTROL_ACCESS RIGHT_DS_READ_PROPERTY RIGHT_DS_DELETE_CHILD]
        UnchangedFlags: [RIGHT_DS_LIST_OBJECT RIGHT_DS_CREATE_CHILD RIGHT_DS_WRITE_PROPERTY RIGHT_DS_WRITE_PROPERTY_EXTENDED RIGHT_READ_CONTROL]

=== Security Descriptor Dump: ./test_cases/root_domain/sd-domainroot.bin ===

Owner: S-1-5-32-544 (BUILTIN\Administrators)
Group: S-1-5-32-544 (BUILTIN\Administrators)
Control: 0x8404

DACL (58 ACEs):

  [0]   AccessDeniedACE:
    SID:   S-1-1-0 (Everyone)
    Mask:  0x00000002
    Flags: [RIGHT_DS_DELETE_CHILD]

  [1]   AccessAllowedACE:
    SID:   S-1-1-0 (Everyone)
    Mask:  0x00000010
    Flags: [RIGHT_DS_READ_PROPERTY]

  [2]   AccessAllowedACE:
    SID:   S-1-5-9 (Enterprise Domain Controllers)
    Mask:  0x00020094
    Flags: [RIGHT_DS_READ_PROPERTY RIGHT_READ_CONTROL RIGHT_DS_LIST_OBJECT RIGHT_DS_LIST_CONTENTS]

  [3]   AccessAllowedACE:
    SID:   S-1-5-11 (Authenticated Users)
    Mask:  0x00020094
    Flags: [RIGHT_DS_LIST_CONTENTS RIGHT_DS_LIST_OBJECT RIGHT_DS_READ_PROPERTY RIGHT_READ_CONTROL]

  [4]   AccessAllowedACE:
    SID:   S-1-5-18 (Local System)
    Mask:  0x000F01FF
    Flags: [RIGHT_DS_CREATE_CHILD RIGHT_DS_WRITE_PROPERTY_EXTENDED RIGHT_DS_READ_PROPERTY RIGHT_WRITE_OWNER RIGHT_DS_LIST_OBJECT RIGHT_DS_DELETE_CHILD RIGHT_DS_DELETE_TREE RIGHT_DS_CONTROL_ACCESS RIGHT_READ_CONTROL RIGHT_DS_LIST_CONTENTS RIGHT_DS_WRITE_PROPERTY RIGHT_DELETE RIGHT_WRITE_DAC]

  [5]   AccessAllowedACE:
    SID:   S-1-5-32-544 (BUILTIN\Administrators)
    Mask:  0x000F01BD
    Flags: [RIGHT_WRITE_DAC RIGHT_WRITE_OWNER RIGHT_DS_CREATE_CHILD RIGHT_DS_WRITE_PROPERTY RIGHT_DS_LIST_CONTENTS RIGHT_DS_WRITE_PROPERTY_EXTENDED RIGHT_DS_LIST_OBJECT RIGHT_DELETE RIGHT_DS_READ_PROPERTY RIGHT_READ_CONTROL RIGHT_DS_CONTROL_ACCESS]

  [6]   AccessAllowedACE:
    SID:   S-1-5-32-554 (BUILTIN\Pre-Windows 2000 Compatible Access)
    Mask:  0x00020010
    Flags: [RIGHT_DS_READ_PROPERTY RIGHT_READ_CONTROL]

  [7]   AccessAllowedACE:
    SID:   S-1-5-32-554 (BUILTIN\Pre-Windows 2000 Compatible Access)
    Mask:  0x00000004
    Flags: [RIGHT_DS_LIST_CONTENTS]

  [8]   AccessAllowedACE:
    SID:   S-1-5-21-75115020-4145467708-3593911600-512 (Domain Admins (CN=Domain Admins,CN=Users,DC=dom1,DC=f0oster,DC=com))
    Mask:  0x000E01BD
    Flags: [RIGHT_DS_WRITE_PROPERTY_EXTENDED RIGHT_DS_READ_PROPERTY RIGHT_DS_WRITE_PROPERTY RIGHT_DS_CONTROL_ACCESS RIGHT_WRITE_DAC RIGHT_DS_CREATE_CHILD RIGHT_DS_LIST_CONTENTS RIGHT_READ_CONTROL RIGHT_WRITE_OWNER RIGHT_DS_LIST_OBJECT]

  [9]   AccessAllowedACE:
    SID:   S-1-5-21-75115020-4145467708-3593911600-519 (Enterprise Admins (CN=Enterprise Admins,CN=Users,DC=dom1,DC=f0oster,DC=com))
    Mask:  0x000F01FF
    Flags: [RIGHT_DS_WRITE_PROPERTY RIGHT_DS_LIST_OBJECT RIGHT_DS_CONTROL_ACCESS RIGHT_WRITE_DAC RIGHT_WRITE_OWNER RIGHT_DS_CREATE_CHILD RIGHT_DS_LIST_CONTENTS RIGHT_DS_WRITE_PROPERTY_EXTENDED RIGHT_DS_READ_PROPERTY RIGHT_READ_CONTROL RIGHT_DS_DELETE_CHILD RIGHT_DS_DELETE_TREE RIGHT_DELETE]

  [10]   AccessAllowedACE:
    SID:   S-1-5-21-75115020-4145467708-3593911600-2604 (svc-changetracking (CN=svc-changetracking,OU=ServiceAccounts,OU=Accounts,OU=Tier1,DC=dom1,DC=f0oster,DC=com))
    Mask:  0x00020014
    Flags: [RIGHT_DS_READ_PROPERTY RIGHT_DS_LIST_CONTENTS RIGHT_READ_CONTROL]

  [11]   AccessAllowedObjectACE:
    SID:   S-1-3-0 (Creator Owner)
    Mask:  0x00000008
    Flags: [RIGHT_DS_WRITE_PROPERTY_EXTENDED]
    ObjectType: Validated write to computer attributes. (9B026DA6-0D3C-465C-8BEE-5199D7165CBA) [validatedWrite]
                Applies to: BF967A86-0DE6-11D0-A285-00AA003049E2
    InheritedObjectType: Computer (BF967A86-0DE6-11D0-A285-00AA003049E2) [class]

  [12]   AccessAllowedObjectACE:
    SID:   S-1-5-9 (Enterprise Domain Controllers)
    Mask:  0x00000100
    Flags: [RIGHT_DS_CONTROL_ACCESS]
    ObjectType: DS-Replication-Get-Changes-In-Filtered-Set (89E95B76-444D-4C62-991A-0FACBEDA640C) [extendedRight]
                Description: Replicate directory changes in a filtered set (Read-Only Domain Controllers).
                Applies to: Domain-DNS, Configuration, DMD

  [13]   AccessAllowedObjectACE:
    SID:   S-1-5-9 (Enterprise Domain Controllers)
    Mask:  0x00000100
    Flags: [RIGHT_DS_CONTROL_ACCESS]
    ObjectType: DS-Replication-Get-Changes (1131F6AA-9C07-11D1-F79F-00C04FC2DCD2) [extendedRight]
                Description: Replicate directory changes from a naming context. Required for DCSync attacks.
                Applies to: Domain-DNS, Configuration, DMD

  [14]   AccessAllowedObjectACE:
    SID:   S-1-5-9 (Enterprise Domain Controllers)
    Mask:  0x00000100
    Flags: [RIGHT_DS_CONTROL_ACCESS]
    ObjectType: DS-Replication-Manage-Topology (1131F6AB-9C07-11D1-F79F-00C04FC2DCD2) [extendedRight]
                Description: Manage replication topology and trigger replication between domain controllers.
                Applies to: Domain-DNS, Configuration, DMD

  [15]   AccessAllowedObjectACE:
    SID:   S-1-5-9 (Enterprise Domain Controllers)
    Mask:  0x00000010
    Flags: [RIGHT_DS_READ_PROPERTY]
    ObjectType: Token-Groups (B7C69E6D-2CC7-11D2-854E-00A0C983F608) [attribute]
    InheritedObjectType: User (BF967ABA-0DE6-11D0-A285-00AA003049E2) [class]

  [16]   AccessAllowedObjectACE:
    SID:   S-1-5-9 (Enterprise Domain Controllers)
    Mask:  0x00000010
    Flags: [RIGHT_DS_READ_PROPERTY]
    ObjectType: Token-Groups (B7C69E6D-2CC7-11D2-854E-00A0C983F608) [attribute]
    InheritedObjectType: Group (BF967A9C-0DE6-11D0-A285-00AA003049E2) [class]

  [17]   AccessAllowedObjectACE:
    SID:   S-1-5-9 (Enterprise Domain Controllers)
    Mask:  0x00000100
    Flags: [RIGHT_DS_CONTROL_ACCESS]
    ObjectType: DS-Check-Stale-Phantoms (1131F6AE-9C07-11D1-F79F-00C04FC2DCD2) [extendedRight]

  [18]   AccessAllowedObjectACE:
    SID:   S-1-5-9 (Enterprise Domain Controllers)
    Mask:  0x00000100
    Flags: [RIGHT_DS_CONTROL_ACCESS]
    ObjectType: DS-Replication-Synchronize (1131F6AC-9C07-11D1-F79F-00C04FC2DCD2) [extendedRight]
                Description: Synchronize replication with a naming context.
                Applies to: Domain-DNS, Configuration, DMD

  [19]   AccessAllowedObjectACE:
    SID:   S-1-5-9 (Enterprise Domain Controllers)
    Mask:  0x00000010
    Flags: [RIGHT_DS_READ_PROPERTY]
    ObjectType: Token-Groups (B7C69E6D-2CC7-11D2-854E-00A0C983F608) [attribute]
    InheritedObjectType: Computer (BF967A86-0DE6-11D0-A285-00AA003049E2) [class]

  [20]   AccessAllowedObjectACE:
    SID:   S-1-5-10 (Principal Self)
    Mask:  0x00000008
    Flags: [RIGHT_DS_WRITE_PROPERTY_EXTENDED]
    ObjectType: Validated write to computer attributes. (9B026DA6-0D3C-465C-8BEE-5199D7165CBA) [validatedWrite]
                Applies to: BF967A86-0DE6-11D0-A285-00AA003049E2
    InheritedObjectType: Computer (BF967A86-0DE6-11D0-A285-00AA003049E2) [class]

  [21]   AccessAllowedObjectACE:
    SID:   S-1-5-10 (Principal Self)
    Mask:  0x00000030
    Flags: [RIGHT_DS_READ_PROPERTY RIGHT_DS_WRITE_PROPERTY]
    ObjectType: msDS-AllowedToActOnBehalfOfOtherIdentity (3F78C3E5-F79A-46BD-A0B8-9D18116DDC79) [attribute]
                Description: Resource-based constrained delegation. Write access enables RBCD attacks for privilege escalation.

  [22]   AccessAllowedObjectACE:
    SID:   S-1-5-10 (Principal Self)
    Mask:  0x00000130
    Flags: [RIGHT_DS_READ_PROPERTY RIGHT_DS_WRITE_PROPERTY RIGHT_DS_CONTROL_ACCESS]
    ObjectType: Phone-and-Mail-Options (91E647DE-D96F-4B70-9557-D63FF4F3CCD8) [propertySet]

  [23]   AccessAllowedObjectACE:
    SID:   S-1-5-10 (Principal Self)
    Mask:  0x00000020
    Flags: [RIGHT_DS_WRITE_PROPERTY]
    ObjectType: ms-TPM-Tpm-Information-For-Computer (EA1B7B93-5E48-46D5-BC6C-4DF4FDA78A35) [attribute]
    InheritedObjectType: Computer (BF967A86-0DE6-11D0-A285-00AA003049E2) [class]

  [24]   AccessAllowedObjectACE:
    SID:   S-1-5-11 (Authenticated Users)
    Mask:  0x00000100
    Flags: [RIGHT_DS_CONTROL_ACCESS]
    ObjectType: Enable-Per-User-Reversibly-Encrypted-Password (05C74C5E-4DEB-43B4-BD9F-86664C2A7FD5) [extendedRight]

  [25]   AccessAllowedObjectACE:
    SID:   S-1-5-11 (Authenticated Users)
    Mask:  0x00000100
    Flags: [RIGHT_DS_CONTROL_ACCESS]
    ObjectType: Unexpire-Password (Alt) (CCC2DC7D-A6AD-4A7A-8846-C04E3CC53501) [extendedRight]
                Description: Unexpire a user's password (alternate GUID).

  [26]   AccessAllowedObjectACE:
    SID:   S-1-5-11 (Authenticated Users)
    Mask:  0x00000100
    Flags: [RIGHT_DS_CONTROL_ACCESS]
    ObjectType: Unexpire-Password (280F369C-67C7-438E-AE98-1D46F3C6F541) [extendedRight]
                Description: Unexpire a user's password.
                Applies to: Domain-DNS

  [27]   AccessAllowedObjectACE:
    SID:   S-1-5-32-544 (BUILTIN\Administrators)
    Mask:  0x00000100
    Flags: [RIGHT_DS_CONTROL_ACCESS]
    ObjectType: DS-Check-Stale-Phantoms (1131F6AE-9C07-11D1-F79F-00C04FC2DCD2) [extendedRight]

  [28]   AccessAllowedObjectACE:
    SID:   S-1-5-32-544 (BUILTIN\Administrators)
    Mask:  0x00000100
    Flags: [RIGHT_DS_CONTROL_ACCESS]
    ObjectType: DS-Replication-Get-Changes-In-Filtered-Set (89E95B76-444D-4C62-991A-0FACBEDA640C) [extendedRight]
                Description: Replicate directory changes in a filtered set (Read-Only Domain Controllers).
                Applies to: Domain-DNS, Configuration, DMD

  [29]   AccessAllowedObjectACE:
    SID:   S-1-5-32-544 (BUILTIN\Administrators)
    Mask:  0x00000100
    Flags: [RIGHT_DS_CONTROL_ACCESS]
    ObjectType: DS-Replication-Get-Changes (1131F6AA-9C07-11D1-F79F-00C04FC2DCD2) [extendedRight]
                Description: Replicate directory changes from a naming context. Required for DCSync attacks.
                Applies to: Domain-DNS, Configuration, DMD

  [30]   AccessAllowedObjectACE:
    SID:   S-1-5-32-544 (BUILTIN\Administrators)
    Mask:  0x00000100
    Flags: [RIGHT_DS_CONTROL_ACCESS]
    ObjectType: DS-Replication-Manage-Topology (1131F6AB-9C07-11D1-F79F-00C04FC2DCD2) [extendedRight]
                Description: Manage replication topology and trigger replication between domain controllers.
                Applies to: Domain-DNS, Configuration, DMD

  [31]   AccessAllowedObjectACE:
    SID:   S-1-5-32-544 (BUILTIN\Administrators)
    Mask:  0x00000100
    Flags: [RIGHT_DS_CONTROL_ACCESS]
    ObjectType: DS-Replication-Synchronize (1131F6AC-9C07-11D1-F79F-00C04FC2DCD2) [extendedRight]
                Description: Synchronize replication with a naming context.
                Applies to: Domain-DNS, Configuration, DMD

  [32]   AccessAllowedObjectACE:
    SID:   S-1-5-32-544 (BUILTIN\Administrators)
    Mask:  0x00000100
    Flags: [RIGHT_DS_CONTROL_ACCESS]
    ObjectType: DS-Replication-Get-Changes-All (1131F6AD-9C07-11D1-F79F-00C04FC2DCD2) [extendedRight]
                Description: Replicate all directory changes including secrets (passwords). Critical for DCSync.
                Applies to: Domain-DNS, Configuration, DMD

  [33]   AccessAllowedObjectACE:
    SID:   S-1-5-32-554 (BUILTIN\Pre-Windows 2000 Compatible Access)
    Mask:  0x00000010
    Flags: [RIGHT_DS_READ_PROPERTY]
    ObjectType: General-Information (59BA2F42-79A2-11D0-9020-00C04FC2D3CF) [propertySet]
                Description: Read/write general information attributes (displayName, description, etc.).
    InheritedObjectType: User (BF967ABA-0DE6-11D0-A285-00AA003049E2) [class]

  [34]   AccessAllowedObjectACE:
    SID:   S-1-5-32-554 (BUILTIN\Pre-Windows 2000 Compatible Access)
    Mask:  0x00000010
    Flags: [RIGHT_DS_READ_PROPERTY]
    ObjectType: General-Information (59BA2F42-79A2-11D0-9020-00C04FC2D3CF) [propertySet]
                Description: Read/write general information attributes (displayName, description, etc.).
    InheritedObjectType: inetOrgPerson (4828CC14-1437-45BC-9B07-AD6F015E5F28) [class]

  [35]   AccessAllowedObjectACE:
    SID:   S-1-5-32-554 (BUILTIN\Pre-Windows 2000 Compatible Access)
    Mask:  0x00020094
    Flags: [RIGHT_READ_CONTROL RIGHT_DS_LIST_CONTENTS RIGHT_DS_READ_PROPERTY RIGHT_DS_LIST_OBJECT]
    InheritedObjectType: inetOrgPerson (4828CC14-1437-45BC-9B07-AD6F015E5F28) [class]

  [36]   AccessAllowedObjectACE:
    SID:   S-1-5-32-554 (BUILTIN\Pre-Windows 2000 Compatible Access)
    Mask:  0x00020094
    Flags: [RIGHT_DS_READ_PROPERTY RIGHT_DS_LIST_OBJECT RIGHT_DS_LIST_CONTENTS RIGHT_READ_CONTROL]
    InheritedObjectType: Group (BF967A9C-0DE6-11D0-A285-00AA003049E2) [class]

  [37]   AccessAllowedObjectACE:
    SID:   S-1-5-32-554 (BUILTIN\Pre-Windows 2000 Compatible Access)
    Mask:  0x00020094
    Flags: [RIGHT_DS_LIST_OBJECT RIGHT_DS_LIST_CONTENTS RIGHT_DS_READ_PROPERTY RIGHT_READ_CONTROL]
    InheritedObjectType: User (BF967ABA-0DE6-11D0-A285-00AA003049E2) [class]

  [38]   AccessAllowedObjectACE:
    SID:   S-1-5-32-554 (BUILTIN\Pre-Windows 2000 Compatible Access)
    Mask:  0x00000010
    Flags: [RIGHT_DS_READ_PROPERTY]
    ObjectType: RAS-Information (037088F8-0AE1-11D2-B422-00A0C968F939) [extendedRight]
    InheritedObjectType: inetOrgPerson (4828CC14-1437-45BC-9B07-AD6F015E5F28) [class]

  [39]   AccessAllowedObjectACE:
    SID:   S-1-5-32-554 (BUILTIN\Pre-Windows 2000 Compatible Access)
    Mask:  0x00000010
    Flags: [RIGHT_DS_READ_PROPERTY]
    ObjectType: Membership (BC0AC240-79A9-11D0-9020-00C04FC2D4CF) [extendedRight]
                Description: Read group membership information.
                Applies to: Group
    InheritedObjectType: inetOrgPerson (4828CC14-1437-45BC-9B07-AD6F015E5F28) [class]

  [40]   AccessAllowedObjectACE:
    SID:   S-1-5-32-554 (BUILTIN\Pre-Windows 2000 Compatible Access)
    Mask:  0x00000010
    Flags: [RIGHT_DS_READ_PROPERTY]
    ObjectType: Logon-Information (5F202010-79A5-11D0-9020-00C04FC2D4CF) [propertySet]
                Description: Read/write logon information attributes (logonHours, userWorkstations, etc.).
                Applies to: User, Computer
    InheritedObjectType: User (BF967ABA-0DE6-11D0-A285-00AA003049E2) [class]

  [41]   AccessAllowedObjectACE:
    SID:   S-1-5-32-554 (BUILTIN\Pre-Windows 2000 Compatible Access)
    Mask:  0x00000010
    Flags: [RIGHT_DS_READ_PROPERTY]
    ObjectType: User-Account-Restrictions (4C164200-20C0-11D0-A768-00AA006E0529) [propertySet]
                Description: Read/write user account restriction attributes (userAccountControl, accountExpires, etc.).
                Applies to: User, Computer
    InheritedObjectType: inetOrgPerson (4828CC14-1437-45BC-9B07-AD6F015E5F28) [class]

  [42]   AccessAllowedObjectACE:
    SID:   S-1-5-32-554 (BUILTIN\Pre-Windows 2000 Compatible Access)
    Mask:  0x00000010
    Flags: [RIGHT_DS_READ_PROPERTY]
    ObjectType: Logon-Information (5F202010-79A5-11D0-9020-00C04FC2D4CF) [propertySet]
                Description: Read/write logon information attributes (logonHours, userWorkstations, etc.).
                Applies to: User, Computer
    InheritedObjectType: inetOrgPerson (4828CC14-1437-45BC-9B07-AD6F015E5F28) [class]

  [43]   AccessAllowedObjectACE:
    SID:   S-1-5-32-557 (BUILTIN\Incoming Forest Trust Builders)
    Mask:  0x00000100
    Flags: [RIGHT_DS_CONTROL_ACCESS]
    ObjectType: Create Inbound Forest Trust (E2A36DC9-AE17-47C3-B58B-BE34C55BA633) [extendedRight]
                Applies to: 19195A5B-6DA0-11D0-AFD3-00C04FD930C9

  [44]   AccessAllowedObjectACE:
    SID:   S-1-5-21-75115020-4145467708-3593911600-498 (Enterprise Read-only Domain Controllers (CN=Enterprise Read-only Domain Controllers,CN=Users,DC=dom1,DC=f0oster,DC=com))
    Mask:  0x00000100
    Flags: [RIGHT_DS_CONTROL_ACCESS]
    ObjectType: DS-Replication-Get-Changes (1131F6AA-9C07-11D1-F79F-00C04FC2DCD2) [extendedRight]
                Description: Replicate directory changes from a naming context. Required for DCSync attacks.
                Applies to: Domain-DNS, Configuration, DMD

  [45]   AccessAllowedObjectACE:
    SID:   S-1-5-21-75115020-4145467708-3593911600-516 (Domain Controllers (CN=Domain Controllers,CN=Users,DC=dom1,DC=f0oster,DC=com))
    Mask:  0x00000100
    Flags: [RIGHT_DS_CONTROL_ACCESS]
    ObjectType: DS-Replication-Get-Changes-All (1131F6AD-9C07-11D1-F79F-00C04FC2DCD2) [extendedRight]
                Description: Replicate all directory changes including secrets (passwords). Critical for DCSync.
                Applies to: Domain-DNS, Configuration, DMD

  [46]   AccessAllowedObjectACE:
    SID:   S-1-5-21-75115020-4145467708-3593911600-522 (Cloneable Domain Controllers (CN=Cloneable Domain Controllers,CN=Users,DC=dom1,DC=f0oster,DC=com))
    Mask:  0x00000100
    Flags: [RIGHT_DS_CONTROL_ACCESS]
    ObjectType: Allow a DC to create a clone of itself (3E0F7E18-2C7A-4C10-BA82-4D926DB99A3E) [extendedRight]
                Applies to: 19195A5B-6DA0-11D0-AFD3-00C04FD930C9

  [47]   AccessAllowedObjectACE:
    SID:   S-1-5-21-75115020-4145467708-3593911600-526 (Key Admins (CN=Key Admins,CN=Users,DC=dom1,DC=f0oster,DC=com))
    Mask:  0x00000030
    Flags: [RIGHT_DS_WRITE_PROPERTY RIGHT_DS_READ_PROPERTY]
    ObjectType: msDS-KeyCredentialLink (5B47D60F-6090-40B2-9F37-2A4DE88F3063) [attribute]
                Description: Shadow Credentials attribute. Write access enables Shadow Credentials attack for auth as the target.

  [48]   AccessAllowedObjectACE:
    SID:   S-1-5-21-75115020-4145467708-3593911600-527 (Enterprise Key Admins (CN=Enterprise Key Admins,CN=Users,DC=dom1,DC=f0oster,DC=com))
    Mask:  0x00000030
    Flags: [RIGHT_DS_READ_PROPERTY RIGHT_DS_WRITE_PROPERTY]
    ObjectType: msDS-KeyCredentialLink (5B47D60F-6090-40B2-9F37-2A4DE88F3063) [attribute]
                Description: Shadow Credentials attribute. Write access enables Shadow Credentials attack for auth as the target.

  [49]   AccessAllowedObjectACE:
    SID:   S-1-5-21-75115020-4145467708-3593911600-2604 (svc-changetracking (CN=svc-changetracking,OU=ServiceAccounts,OU=Accounts,OU=Tier1,DC=dom1,DC=f0oster,DC=com))
    Mask:  0x00000100
    Flags: [RIGHT_DS_CONTROL_ACCESS]
    ObjectType: Reanimate Tombstones (45EC5156-DB7E-47BB-B53F-DBEB2D03C40F) [extendedRight]
                Applies to: BF967A8F-0DE6-11D0-A285-00AA003049E2, BF967A87-0DE6-11D0-A285-00AA003049E2, 19195A5B-6DA0-11D0-AFD3-00C04FD930C9

  [50]   AccessAllowedObjectACE:
    SID:   S-1-5-21-75115020-4145467708-3593911600-3601 (MSOL_d022ac9a75bd (CN=MSOL_d022ac9a75bd,OU=Identities,OU=Tier0,DC=dom1,DC=f0oster,DC=com))
    Mask:  0x00000030
    Flags: [RIGHT_DS_READ_PROPERTY RIGHT_DS_WRITE_PROPERTY]
    InheritedObjectType: inetOrgPerson (4828CC14-1437-45BC-9B07-AD6F015E5F28) [class]

  [51]   AccessAllowedObjectACE:
    SID:   S-1-5-21-75115020-4145467708-3593911600-3601 (MSOL_d022ac9a75bd (CN=MSOL_d022ac9a75bd,OU=Identities,OU=Tier0,DC=dom1,DC=f0oster,DC=com))
    Mask:  0x00000100
    Flags: [RIGHT_DS_CONTROL_ACCESS]
    ObjectType: DS-Replication-Get-Changes (1131F6AA-9C07-11D1-F79F-00C04FC2DCD2) [extendedRight]
                Description: Replicate directory changes from a naming context. Required for DCSync attacks.
                Applies to: Domain-DNS, Configuration, DMD

  [52]   AccessAllowedObjectACE:
    SID:   S-1-5-21-75115020-4145467708-3593911600-3601 (MSOL_d022ac9a75bd (CN=MSOL_d022ac9a75bd,OU=Identities,OU=Tier0,DC=dom1,DC=f0oster,DC=com))
    Mask:  0x00000100
    Flags: [RIGHT_DS_CONTROL_ACCESS]
    ObjectType: DS-Replication-Get-Changes-All (1131F6AD-9C07-11D1-F79F-00C04FC2DCD2) [extendedRight]
                Description: Replicate all directory changes including secrets (passwords). Critical for DCSync.
                Applies to: Domain-DNS, Configuration, DMD

  [53]   AccessAllowedObjectACE:
    SID:   S-1-5-21-75115020-4145467708-3593911600-3601 (MSOL_d022ac9a75bd (CN=MSOL_d022ac9a75bd,OU=Identities,OU=Tier0,DC=dom1,DC=f0oster,DC=com))
    Mask:  0x00000030
    Flags: [RIGHT_DS_READ_PROPERTY RIGHT_DS_WRITE_PROPERTY]
    InheritedObjectType: Group (BF967A9C-0DE6-11D0-A285-00AA003049E2) [class]

  [54]   AccessAllowedObjectACE:
    SID:   S-1-5-21-75115020-4145467708-3593911600-3601 (MSOL_d022ac9a75bd (CN=MSOL_d022ac9a75bd,OU=Identities,OU=Tier0,DC=dom1,DC=f0oster,DC=com))
    Mask:  0x00000030
    Flags: [RIGHT_DS_READ_PROPERTY RIGHT_DS_WRITE_PROPERTY]
    InheritedObjectType: User (BF967ABA-0DE6-11D0-A285-00AA003049E2) [class]

  [55]   AccessAllowedObjectACE:
    SID:   S-1-5-21-75115020-4145467708-3593911600-3601 (MSOL_d022ac9a75bd (CN=MSOL_d022ac9a75bd,OU=Identities,OU=Tier0,DC=dom1,DC=f0oster,DC=com))
    Mask:  0x00000030
    Flags: [RIGHT_DS_WRITE_PROPERTY RIGHT_DS_READ_PROPERTY]
    InheritedObjectType: Group-Policy-Container (5CB41ED0-0E4C-11D0-A286-00AA003049E2) [class]

  [56]   AccessAllowedObjectACE:
    SID:   S-1-5-21-75115020-4145467708-3593911600-3601 (MSOL_d022ac9a75bd (CN=MSOL_d022ac9a75bd,OU=Identities,OU=Tier0,DC=dom1,DC=f0oster,DC=com))
    Mask:  0x00000020
    Flags: [RIGHT_DS_WRITE_PROPERTY]
    ObjectType: msDS-KeyCredentialLink (5B47D60F-6090-40B2-9F37-2A4DE88F3063) [attribute]
                Description: Shadow Credentials attribute. Write access enables Shadow Credentials attack for auth as the target.
    InheritedObjectType: ms-DS-Device (5DF2B673-6D41-4774-B3E8-D52E8EE9FF99) [class]

  [57]   AccessAllowedObjectACE:
    SID:   S-1-5-21-75115020-4145467708-3593911600-3601 (MSOL_d022ac9a75bd (CN=MSOL_d022ac9a75bd,OU=Identities,OU=Tier0,DC=dom1,DC=f0oster,DC=com))
    Mask:  0x00000100
    Flags: [RIGHT_DS_CONTROL_ACCESS]
    ObjectType: User-Force-Change-Password (00299570-246D-11D0-A768-00AA006E0529) [extendedRight]
                Description: Reset a user's password without knowing the current password.
                Applies to: User, Computer, ms-DS-Group-Managed-Service-Account
    InheritedObjectType: User (BF967ABA-0DE6-11D0-A285-00AA003049E2) [class]
```