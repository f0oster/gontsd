<#
.SYNOPSIS
    Generates binary security descriptor test fixtures for gontsd.

.DESCRIPTION
    Builds SDDL strings covering all 9 ACE types that Windows can produce,
    converts them to binary via the Win32 API, and writes .bin files.

    Fixture coverage:

      DACL                                          SDDL
      0x00  ACCESS_ALLOWED_ACE                      A
      0x01  ACCESS_DENIED_ACE                       D
      0x05  ACCESS_ALLOWED_OBJECT_ACE               OA   (3 GUID flag combos)
      0x06  ACCESS_DENIED_OBJECT_ACE                OD
      0x09  ACCESS_ALLOWED_CALLBACK_ACE             XA
      0x0A  ACCESS_DENIED_CALLBACK_ACE              XD
      0x0B  ACCESS_ALLOWED_CALLBACK_OBJECT_ACE      ZA

      SACL
      0x02  SYSTEM_AUDIT_ACE                        AU
      0x07  SYSTEM_AUDIT_OBJECT_ACE                 OU

    0x0C (ACCESS_DENIED_CALLBACK_OBJECT_ACE) has no SDDL token. It can be
    created via AddConditionalAce or raw SD manipulation, but no common
    high-level workflow produces one. Tested with synthetic bytes in Go.

.PARAMETER OutputPath
    Where to write .bin files. Defaults to testdata\ under the repo root.

.EXAMPLE
    .\New-TestFixtures.ps1
    .\New-TestFixtures.ps1 -OutputPath C:\scratch\fixtures
#>

[CmdletBinding()]
param(
    [string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

$ScriptDir = Split-Path -Parent $PSScriptRoot
if (-not $OutputPath) {
    $OutputPath = Join-Path $ScriptDir "testdata"
}

# Synthetic domain SID -- consistent across fixtures, not tied to a real domain.
$DomainSid    = "S-1-5-21-1000-2000-3000"
$DomainAdmins = "$DomainSid-512"
$DomainUsers  = "$DomainSid-513"

# SDDL aliases used inline: SY (SYSTEM), WD (Everyone), AU (Auth Users), PS (Self)

# Schema GUIDs (from MS-ADTS)
$GuidResetPassword  = "00299570-246d-11d0-a768-00aa006e0529"  # Extended right
$GuidChangePassword = "ab721a53-1e2f-11d0-9819-00aa0040529b"  # Extended right
$GuidPersonalInfo   = "77b5b886-944a-11d1-aebd-0000f80367c1"  # Property set
$GuidDescription    = "bf967950-0de6-11d0-a285-00aa003049e2"  # Attribute
$GuidUserClass      = "bf967aba-0de6-11d0-a285-00aa003049e2"  # Class
$GuidComputerClass  = "bf967a86-0de6-11d0-a285-00aa003049e2"  # Class
$GuidMember         = "bf9679c0-0de6-11d0-a285-00aa003049e2"  # Attribute

# ---------------------------------------------------------------------------
# Win32 P/Invoke
#
# .NET's RawSecurityDescriptor can't parse conditional ACE syntax (XA/XD/ZA).
# The Win32 API handles everything, so we use it for all fixtures.
# ---------------------------------------------------------------------------

Add-Type -TypeDefinition @"
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

public static class Win32SD {
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
        string StringSecurityDescriptor,
        uint StringSDRevision,
        out IntPtr SecurityDescriptor,
        out uint SecurityDescriptorSize);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr hMem);

    public static byte[] SddlToBytes(string sddl) {
        IntPtr pSD;
        uint size;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1, out pSD, out size))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        byte[] bytes = new byte[size];
        Marshal.Copy(pSD, bytes, 0, (int)size);
        LocalFree(pSD);
        return bytes;
    }
}
"@

function Export-SddlFixture {
    <#
    .SYNOPSIS Converts SDDL to binary and writes it to a file.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Sddl,

        [Parameter(Mandatory)]
        [string]$OutFile
    )

    $Dir = Split-Path $OutFile
    if (-not (Test-Path $Dir)) {
        New-Item -ItemType Directory -Path $Dir -Force | Out-Null
    }

    $Bytes = [Win32SD]::SddlToBytes($Sddl)
    [System.IO.File]::WriteAllBytes($OutFile, $Bytes)
    Write-Host "  Exported $($Bytes.Length) bytes -> $OutFile"
}

# ---------------------------------------------------------------------------
# 1. object_aces -- simple and object ACEs with all GUID flag combinations
#
# DACL (7 ACEs, canonical order: deny first, then allow):
#   [0]  AccessDenied          Everyone       Delete
#   [1]  AccessDeniedObject    Everyone       ExtendedRight   ObjectType=Change-Password
#   [2]  AccessDeniedObject    Domain Users   WriteProperty   ObjectType=Member  InheritedObjectType=User  (CI)
#   [3]  AccessAllowed         SYSTEM         GenericAll
#   [4]  AccessAllowedObject   Auth Users     ExtendedRight   ObjectType=Reset-Password
#   [5]  AccessAllowedObject   Domain Admins  GenericAll      InheritedObjectType=User  (CI)
#   [6]  AccessAllowedObject   Self           WriteProperty   ObjectType=Description  InheritedObjectType=Computer  (CI)
#
# Object ACEs exercise all three GUID flag states:
#   [1],[4]  ObjectType only          (flags=0x01)
#   [5]      InheritedObjectType only (flags=0x02)
#   [2],[6]  Both GUIDs               (flags=0x03)
# ---------------------------------------------------------------------------

Write-Host "`n=== object_aces ===" -ForegroundColor Cyan

$ObjectAcesSddl = @(
    "O:SY"
    "G:SY"
    "D:"
    "(D;;SD;;;WD)"
    "(OD;;CR;$GuidChangePassword;;WD)"
    "(OD;CI;WP;$GuidMember;$GuidUserClass;$DomainUsers)"
    "(A;;GA;;;SY)"
    "(OA;;CR;$GuidResetPassword;;AU)"
    "(OA;CI;GA;;$GuidUserClass;$DomainAdmins)"
    "(OA;CI;WP;$GuidDescription;$GuidComputerClass;PS)"
) -join ""

$ExportParams = @{
    Sddl    = $ObjectAcesSddl
    OutFile = Join-Path $OutputPath "object_aces\sd.bin"
}
Export-SddlFixture @ExportParams

# ---------------------------------------------------------------------------
# 2. audit_aces -- SACL with SystemAudit and SystemAuditObject ACEs
#
# DACL (2 ACEs, minimal baseline):
#   [0]  AccessAllowed   SYSTEM         GenericAll
#   [1]  AccessAllowed   Domain Admins  GenericAll
#
# SACL (4 ACEs):
#   [0]  SystemAudit         Everyone    Delete|DeleteTree           SA|FA
#   [1]  SystemAudit         Auth Users  WriteProperty|WriteDacl     FA only
#   [2]  SystemAuditObject   Everyone    ExtendedRight               SA     ObjectType=Reset-Password
#   [3]  SystemAuditObject   Auth Users  WriteProperty               SA|FA  ObjectType=Personal-Info  InheritedObjectType=User  (CI)
# ---------------------------------------------------------------------------

Write-Host "`n=== audit_aces ===" -ForegroundColor Cyan

$AuditAcesSddl = @(
    "O:SY"
    "G:SY"
    "D:"
    "(A;;GA;;;SY)"
    "(A;;GA;;;$DomainAdmins)"
    "S:"
    "(AU;SAFA;SDDT;;;WD)"
    "(AU;FA;WPWD;;;AU)"
    "(OU;SA;CR;$GuidResetPassword;;WD)"
    "(OU;CISAFA;WP;$GuidPersonalInfo;$GuidUserClass;AU)"
) -join ""

$ExportParams = @{
    Sddl    = $AuditAcesSddl
    OutFile = Join-Path $OutputPath "audit_aces\sd.bin"
}
Export-SddlFixture @ExportParams

# ---------------------------------------------------------------------------
# 3. callback_aces -- conditional ACEs with ApplicationData blobs
#
# DACL (5 ACEs):
#   [0]  AccessAllowed                 SYSTEM         GenericAll
#   [1]  AccessAllowed                 Domain Admins  GenericAll
#   [2]  AccessAllowedCallback         Auth Users     GenericAll
#         Condition: Member_of{SID(Domain Admins)}
#   [3]  AccessDeniedCallback          Everyone       WriteProperty
#         Condition: Not_Member_of{SID(Domain Admins)}
#   [4]  AccessAllowedCallbackObject   Auth Users     ReadProperty  ObjectType=Description
#         Condition: Member_of{SID(Domain Admins)}
# ---------------------------------------------------------------------------

Write-Host "`n=== callback_aces ===" -ForegroundColor Cyan

$CallbackAcesSddl = @(
    "O:SY"
    "G:SY"
    "D:"
    "(A;;GA;;;SY)"
    "(A;;GA;;;$DomainAdmins)"
    "(XA;;GA;;;AU;(Member_of{SID($DomainAdmins)}))"
    "(XD;;WP;;;WD;(Not_Member_of{SID($DomainAdmins)}))"
    "(ZA;;RP;$GuidDescription;;AU;(Member_of{SID($DomainAdmins)}))"
) -join ""

$ExportParams = @{
    Sddl    = $CallbackAcesSddl
    OutFile = Join-Path $OutputPath "callback_aces\sd.bin"
}
Export-SddlFixture @ExportParams

# ---------------------------------------------------------------------------
# 4. all_ace_types -- every producible ACE type on one descriptor
#
# DACL (10 ACEs):
#   [0]  AccessDenied                  Everyone      Delete
#   [1]  AccessDeniedObject            Everyone      ExtendedRight   ObjectType=Change-Password
#   [2]  AccessDeniedObject            Domain Users  WriteProperty   ObjectType=Member  InheritedObjectType=User  (CI)
#   [3]  AccessDeniedCallback          Everyone      WriteProperty
#         Condition: Not_Member_of{SID(Domain Admins)}
#   [4]  AccessAllowed                 SYSTEM        GenericAll
#   [5]  AccessAllowedObject           Auth Users    ExtendedRight   ObjectType=Reset-Password
#   [6]  AccessAllowedObject           Self          WriteProperty   ObjectType=Description  InheritedObjectType=User  (CI)
#   [7]  AccessAllowedObject           Domain Admins GenericAll      InheritedObjectType=Computer  (CI)
#   [8]  AccessAllowedCallback         Auth Users    GenericAll
#         Condition: Member_of{SID(Domain Admins)}
#   [9]  AccessAllowedCallbackObject   Auth Users    ReadProperty   ObjectType=Description
#         Condition: Member_of{SID(Domain Admins)}
#
# SACL (3 ACEs):
#   [0]  SystemAudit         Everyone    Delete      SA|FA
#   [1]  SystemAuditObject   Everyone    ExtendedRight  SA  ObjectType=Reset-Password
#   [2]  SystemAuditObject   Auth Users  WriteProperty  SA|FA  ObjectType=Personal-Info  InheritedObjectType=User  (CI)
# ---------------------------------------------------------------------------

Write-Host "`n=== all_ace_types ===" -ForegroundColor Cyan

$AllAceTypesSddl = @(
    "O:SY"
    "G:SY"
    "D:"
    "(D;;SD;;;WD)"
    "(OD;;CR;$GuidChangePassword;;WD)"
    "(OD;CI;WP;$GuidMember;$GuidUserClass;$DomainUsers)"
    "(XD;;WP;;;WD;(Not_Member_of{SID($DomainAdmins)}))"
    "(A;;GA;;;SY)"
    "(OA;;CR;$GuidResetPassword;;AU)"
    "(OA;CI;WP;$GuidDescription;$GuidUserClass;PS)"
    "(OA;CI;GA;;$GuidComputerClass;$DomainAdmins)"
    "(XA;;GA;;;AU;(Member_of{SID($DomainAdmins)}))"
    "(ZA;;RP;$GuidDescription;;AU;(Member_of{SID($DomainAdmins)}))"
    "S:"
    "(AU;SAFA;SD;;;WD)"
    "(OU;SA;CR;$GuidResetPassword;;WD)"
    "(OU;CISAFA;WP;$GuidPersonalInfo;$GuidUserClass;AU)"
) -join ""

$ExportParams = @{
    Sddl    = $AllAceTypesSddl
    OutFile = Join-Path $OutputPath "all_ace_types\sd.bin"
}
Export-SddlFixture @ExportParams

# ---------------------------------------------------------------------------
# 5. compare_add_ace -- before/after pair where an ACE is added
#
# before DACL (2 ACEs):
#   [0]  AccessAllowed   SYSTEM       GenericAll
#   [1]  AccessAllowed   Auth Users   ReadControl
#
# after DACL (3 ACEs):
#   [0]  AccessAllowed   SYSTEM       GenericAll
#   [1]  AccessAllowed   Auth Users   ReadControl
#   [2]  AccessAllowed   Everyone     Delete
# ---------------------------------------------------------------------------

Write-Host "`n=== compare_add_ace ===" -ForegroundColor Cyan

$CompareAddBefore = @("O:SYG:SYD:(A;;GA;;;SY)(A;;RC;;;AU)") -join ""
$CompareAddAfter  = @("O:SYG:SYD:(A;;GA;;;SY)(A;;RC;;;AU)(A;;SD;;;WD)") -join ""

$ExportParams = @{ Sddl = $CompareAddBefore; OutFile = Join-Path $OutputPath "compare_add_ace\before.bin" }
Export-SddlFixture @ExportParams
$ExportParams = @{ Sddl = $CompareAddAfter; OutFile = Join-Path $OutputPath "compare_add_ace\after.bin" }
Export-SddlFixture @ExportParams

# ---------------------------------------------------------------------------
# 6. compare_remove_ace -- before/after pair where an ACE is removed
#
# before DACL (3 ACEs):
#   [0]  AccessAllowed   SYSTEM       GenericAll
#   [1]  AccessAllowed   Auth Users   ReadControl
#   [2]  AccessAllowed   Everyone     Delete
#
# after DACL (2 ACEs):
#   [0]  AccessAllowed   SYSTEM       GenericAll
#   [1]  AccessAllowed   Auth Users   ReadControl
# ---------------------------------------------------------------------------

Write-Host "`n=== compare_remove_ace ===" -ForegroundColor Cyan

$CompareRemoveBefore = @("O:SYG:SYD:(A;;GA;;;SY)(A;;RC;;;AU)(A;;SD;;;WD)") -join ""
$CompareRemoveAfter  = @("O:SYG:SYD:(A;;GA;;;SY)(A;;RC;;;AU)") -join ""

$ExportParams = @{ Sddl = $CompareRemoveBefore; OutFile = Join-Path $OutputPath "compare_remove_ace\before.bin" }
Export-SddlFixture @ExportParams
$ExportParams = @{ Sddl = $CompareRemoveAfter; OutFile = Join-Path $OutputPath "compare_remove_ace\after.bin" }
Export-SddlFixture @ExportParams

# ---------------------------------------------------------------------------
# 7. compare_modify_mask -- before/after pair where an ACE mask changes
#
# before DACL (2 ACEs):
#   [0]  AccessAllowed   SYSTEM       GenericAll
#   [1]  AccessAllowed   Auth Users   ReadControl|ReadProperty|WriteProperty
#
# after DACL (2 ACEs):
#   [0]  AccessAllowed   SYSTEM       GenericAll
#   [1]  AccessAllowed   Auth Users   ReadControl  (RP and WP removed)
# ---------------------------------------------------------------------------

Write-Host "`n=== compare_modify_mask ===" -ForegroundColor Cyan

$CompareModifyBefore = @("O:SYG:SYD:(A;;GA;;;SY)(A;;RCRPWP;;;AU)") -join ""
$CompareModifyAfter  = @("O:SYG:SYD:(A;;GA;;;SY)(A;;RC;;;AU)") -join ""

$ExportParams = @{ Sddl = $CompareModifyBefore; OutFile = Join-Path $OutputPath "compare_modify_mask\before.bin" }
Export-SddlFixture @ExportParams
$ExportParams = @{ Sddl = $CompareModifyAfter; OutFile = Join-Path $OutputPath "compare_modify_mask\after.bin" }
Export-SddlFixture @ExportParams

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------

Write-Host "`n=== Done ===" -ForegroundColor Green
Write-Host "Exported fixtures to: $OutputPath"
Write-Host ""
Write-Host "  object_aces/sd.bin                Simple + Object ACEs (3 GUID flag combos)"
Write-Host "  audit_aces/sd.bin                 SystemAudit + SystemAuditObject in SACL"
Write-Host "  callback_aces/sd.bin              Callback/conditional ACEs (XA, XD, ZA)"
Write-Host "  all_ace_types/sd.bin              All 9 ACE types on one descriptor"
Write-Host "  compare_add_ace/before|after.bin  ACE added between snapshots"
Write-Host "  compare_remove_ace/before|after.bin  ACE removed between snapshots"
Write-Host "  compare_modify_mask/before|after.bin  ACE mask changed between snapshots"
