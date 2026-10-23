<#
================================================================================
 cbptwindows.ps1 -- CyberPatriot Windows image triage + hardening helper
Usage:       Right-click PowerShell -> Run as Administrator -> .\cbptwindows.ps1
If blocked, right click file, properties, Ublock. If still blocked, run this in powershell: Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
================================================================================
 grew out of the team checklist over a bunch of practice rounds. it is NOT
 a magic point button: it automates the boring baseline every team can do,
 then tells you where the rest of the points are. the README and the
 forensic questions are still yours -- and they are worth more than
 anything in this file.

 --------------------------------------------------------------------------------
 WHAT IT DOES
 --------------------------------------------------------------------------------
   1. saves verified configuration snapshots in a private, unique run folder.
      -Restore recovers configuration, not deleted accounts/data, passwords,
      firmware changes, installed features, or a complete running system.
   2. finds and prints the README (authorized users, critical services).
   3. recon + evidence dump -> evidence\ : users, hidden accounts, RID-500
      clones, run keys, IFEO debugger hijacks, scheduled tasks, service
      binPaths, WMI subscriptions, shares + ACLs, listening ports, PII
      patterns, prefetch, USB history, mark-of-the-web, recycle bin,
      browser artifacts, Defender threat history, cleared-log events.
   4. applies the scored baseline -- asks first on anything destructive:
      password/lockout/audit policy via secedit MERGE, the LSA/UAC/SMB/TLS
      registry suite, firewall, SMBv1, insecure services, Defender,
      auditpol, app configs (IIS/Apache/MySQL).
   5. prints a scorecard: PASS/FAIL/WARN + a one-line hint on every
      non-PASS, and exports findings.csv + needs-review.txt.

 --------------------------------------------------------------------------------
 WHAT IT DOES NOT DO (on purpose)
 --------------------------------------------------------------------------------
   * never automatically deletes a user, a file, or a log. account removal
     requires an interactive choice; -Force leaves ambiguous choices for review.
     deleting an authorized user or business data is the fastest way to
     lose points on the image.
   * never clears event logs. that is attacker behavior and it destroys
     your own forensic answers.
   * never blocks cmd/powershell/regedit. locking yourself out of your own
     tooling mid-round costs more than it gains.
   * does not apply secedit policy on a domain controller -- it warns you
     and skips (DC policy lives in the Default Domain Policy GPO).

 --------------------------------------------------------------------------------
 TIERS
 --------------------------------------------------------------------------------
   default      safe scored baseline. run this first, every time.
   -DryRun      no target/configuration changes. only private per-run artifacts
                (including scratch exports for verification) are written.
   -Aggressive  also offers things that can break a critical service
                (RDP off, wide-open firewall rules, server services).
                read the README before using it.
   -Paranoid    recon + backup + verify only; private artifacts are still saved.
   -Force       non-interactive: accepts explicit confirms, skips choices that
                need human judgement/password entry. never overrides either mode.
   -NoBackup    inventory only: refusing backups also refuses mutations.
   -DisableBuiltinAdmin  also disable the RID-500 account. read the README
                first; disabling the account you are using locks you out.
   -NoLolbinBlocks       skip the outbound firewall blocks for mshta,
                wscript, certutil, etc. only if a logon script needs them.

 --------------------------------------------------------------------------------
 USAGE (elevated PowerShell)
 --------------------------------------------------------------------------------
   powershell -NoProfile -ExecutionPolicy Bypass -File .\cbptwindows.ps1
   .\cbptwindows.ps1 -Phase all                # backup -> recon -> harden -> verify
   .\cbptwindows.ps1 -Phase recon -Paranoid    # look, do not touch
   .\cbptwindows.ps1 -Phase users              # one section
   .\cbptwindows.ps1 -DryRun -Phase all        # rehearsal run
   .\cbptwindows.ps1 -Hints                    # the point-scrounging guide
   .\cbptwindows.ps1 -Phase checklist          # closing manual checks
   .\cbptwindows.ps1 -FirewallFile C:\path\custom.wfw   # import local firewall policy
   .\cbptwindows.ps1 -Restore C:\CP\cbptwindows\runs\<stamp>\backup
   # -AdvancedHiveRestore additionally OFFERS raw hive recovery, interactively.

   artifacts: <WorkRoot>\runs\<unique stamp>\ (SYSTEM/Administrators only).
   existing roots must be trusted local directories, never junctions/symlinks.
   standalone and menu changes require a completed backup, once per run.
   DCs or an unknown machine role are inventory-only. ASR/NP/CFA start in
   audit mode; -Aggressive offers blocking. RDP, DB bindings, stronger policies,
   existing cipher lists and unrelated ASR entries are preserved by default.
   event log auto-archives need free disk space and ongoing capacity monitoring.
   recovery requires this machine's completed 1.3.0 backup and its private
   journals; raw SAM/SYSTEM recovery is advanced/offline work, not normal undo.

   sections: recon users registry network services defender apps files
             verify report checklist all menu guide

   the users section reconciles local accounts against users.txt and
   admins.txt placed next to this script (one name per line, copied from
   the README). templates get created on first run if they are missing.

 --------------------------------------------------------------------------------
  CHANGELOG
  --------------------------------------------------------------------------------
   1.3.0  fail-closed modes/roles, private non-overwriting artifacts, verified
          backups and typed configuration recovery; checked native execution
          and its exit codes; principal/policy-preserving merges; corrected
          registry, Defender, firewall/SMB/services, IIS/AppCmd, Apache,
          MySQL, audit policy and event-log rotation checks; section-aware
          database config edits that roll back on failed validation.
   0.9.x  team checklist -> script. secedit MERGE logic after we clobbered
          user rights nobody remembered setting and broke a practice image.
   1.0.0  merged the best of our other helpers: users.txt/admins.txt
          reconciliation, sticky-keys + IFEO backdoor checks, malware hunt
          in recon, -DryRun, needs-review.txt, the master hints guide.
   1.0.1  Get-Service .StartType does not exist on PS 5.1 -> start types
          now go through sc.exe with a cmdlet fallback.
   1.2.0  folded in the PenguinOS checklist: LOLBin outbound firewall
          blocks, Remote Assistance off, legacy service sweep, Office macro
          hardening, Defender sandbox + policy values, resource SACLs,
          crash-dump/attachment/ClearTextPassword fixes, net accounts
          fallback, optional -DisableBuiltinAdmin, a local-only -FirewallFile
          import, Telnet optional-feature cleanup, and a checklist section.
          the original PenguinOS checklist is by yofriendfromschool1.
          deliberately NOT copied: TrustedHosts=*, a permissive PowerShell
          session SDDL, or downloading a firewall .wfw from GitHub.
   1.2.1  closed gaps found in the upstream checklists: guest/pseudo accounts
          are disabled even with empty users.txt/admins.txt, RID-500 password
          check, null-session and Netlogon limits, Microsoft-account block,
          AppLocker/Defender posture findings, inbound-allow firewall
          inventory, TFTP/SimpleTCP/PSv2 cleanup, Apache/POL-APPLY findings.

 known gaps / TODO:
   - domain controller: password policy needs the Default Domain Policy
     GPO. do it by hand in gpmc.msc; the script warns and moves on.
   - BitLocker / Credential Guard: deliberately not attempted. they need
     nested Hyper-V and fail on basically every competition image.
   - the README finder prints candidates; it cannot read your mind.
================================================================================
#>

[CmdletBinding()]
param(
    [ValidateSet('menu','guide','all','recon','users','registry',
                 'network','services','defender','apps','files','verify','report','checklist')]
    [string]$Phase = 'menu',

    [switch]$Aggressive,
    [switch]$Paranoid,
    [switch]$DryRun,
    [switch]$NoBackup,
    [switch]$Force,
    [switch]$Hints,
    [switch]$DisableBuiltinAdmin,
    [switch]$NoLolbinBlocks,
    [switch]$AdvancedHiveRestore,

    [string]$Restore = '',
    [string]$WorkRoot = 'C:\CP\cbptwindows',
    [string]$KeepServices = '',
    [string]$FirewallFile = ''
)

# ------------------------------------------------------------------------------
# globals
# ------------------------------------------------------------------------------
$script:Version    = '1.3.0'
$script:Stamp      = (Get-Date -Format 'yyyyMMdd-HHmmss-fff') + '-' + [guid]::NewGuid().ToString('N')
$script:Root       = Join-Path $WorkRoot ("runs\" + $script:Stamp)
$script:EvidenceRoot = Join-Path $script:Root 'evidence'
$script:EvDir      = $script:EvidenceRoot
$script:BkDir      = Join-Path $script:Root 'backup'
$script:Scratch    = Join-Path $script:Root 'scratch'
$script:LogFile    = Join-Path $script:Root 'cbptwindows.log'
$script:ReviewFile = Join-Path $script:Root   'needs-review.txt'
$script:Findings   = New-Object System.Collections.Generic.List[object]
$script:Changed    = New-Object System.Collections.Generic.List[object]
$script:Hostname   = $env:COMPUTERNAME
$script:Dry        = [bool]$DryRun
$script:ArtifactReady = $false
$script:BackupAttempted = $false
$script:BackupComplete = $false
$script:RecoveryMode = $false
$script:FileJournal = New-Object System.Collections.Generic.List[object]
$script:RegJournal = New-Object System.Collections.Generic.List[object]
$script:RegExports = New-Object System.Collections.Generic.List[object]
$script:IdentitySid = ''

# services that must keep working. EDIT PER IMAGE once you have read the
# README. anything in here is never stopped or disabled by the service pass.
$script:KeepList = @(
    'EventLog','Schedule','RpcSs','RpcEptMapper','SamSs','ProfSvc','Winmgmt',
    'MpsSvc','BFE','WinDefend','SecurityHealthService','wuauserv','BITS',
    'LanmanServer','LanmanWorkstation','Dhcp','Dnscache','CryptSvc','W32Time',
    'NlaSvc','Netlogon','Audiosrv'
)
if ($KeepServices) { $script:KeepList += @($KeepServices -split ',' | ForEach-Object { $_.Trim() }) }

# ------------------------------------------------------------------------------
# output + logging
# ------------------------------------------------------------------------------
function Write-CP {
    param([string]$Message, [ValidateSet('info','ok','warn','err','head','step')][string]$Level = 'info')
    $ts = Get-Date -Format 'HH:mm:ss'
    $color = switch ($Level) {
        'ok'   { 'Green' }  'warn' { 'Yellow' } 'err'  { 'Red' }
        'head' { 'Cyan' }   'step' { 'Magenta' } default { 'Gray' }
    }
    $prefix = switch ($Level) {
        'ok'   { '[+] ' }  'warn' { '[!] ' }  'err'  { '[x] ' }
        'head' { '' }       'step' { '==> ' }  default { '[*] ' }
    }
    try { Write-Host ($prefix + $Message) -ForegroundColor $color } catch {}
    if ($script:ArtifactReady) {
        try { Add-Content -LiteralPath $script:LogFile -Value ("$ts $Level`t$Message") -ErrorAction Stop } catch {}
    }
}

function Write-Banner {
    param([string]$Title)
    $bar = '=' * 78
    Write-Host ''
    Write-Host $bar -ForegroundColor Cyan
    Write-Host (" {0}" -f $Title) -ForegroundColor Cyan
    Write-Host $bar -ForegroundColor Cyan
}

function Add-Finding {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Area,
        [Parameter(Mandatory)][ValidateSet('PASS','FAIL','WARN','INFO','SKIP')][string]$Status,
        [string]$Detail = '',
        [string]$Hint = ''
    )
    $script:Findings.Add([pscustomobject]@{
        Id = $Id; Area = $Area; Status = $Status
        Detail = $Detail; Hint = $Hint; Time = (Get-Date -Format 's')
    })
    $c = switch ($Status) { 'PASS'{'Green'} 'FAIL'{'Red'} 'WARN'{'Yellow'} 'INFO'{'DarkGray'} default{'DarkYellow'} }
    $s = switch ($Status) { 'PASS'{'[+]'} 'FAIL'{'[x]'} 'WARN'{'[!]'} 'INFO'{'[i]'} default{'[-]'} }
    try { Write-Host (" {0} {1,-30} {2}" -f $s, $Id, $Detail) -ForegroundColor $c } catch {}
    if ($Hint -and $Status -ne 'PASS') {
        try { Write-Host ("       hint: {0}" -f $Hint) -ForegroundColor DarkCyan } catch {}
    }
}

function Add-Review {
    # things a human has to decide with the README in hand
    param([string]$Message)
    if ($script:ArtifactReady) {
        Add-Content -LiteralPath $script:ReviewFile -Value ("- " + $Message) -ErrorAction Stop
    }
    Write-CP ("review: {0}" -f $Message) 'warn'
}

function Test-Admin {
    try {
        $id  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $pr  = New-Object System.Security.Principal.WindowsPrincipal($id)
        return $pr.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Confirm-CP {
    param([string]$Question, [switch]$InteractiveOnly)
    if ($Paranoid -or $script:Dry) { return $false }
    if ($Force) {
        if ($InteractiveOnly) { Add-Review "$Question (non-interactive: skipped)"; return $false }
        return $true
    }
    Write-Host ''
    Write-Host ("  !! " + $Question) -ForegroundColor Yellow
    try {
        $r = Read-Host '  type YES to continue'
        return ($r -ceq 'YES')
    } catch { return $false }
}

function Get-CPRole {
    try {
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        if ($null -eq $os.ProductType -or $null -eq $cs.DomainRole) { return 'Unknown' }
        if ($os.ProductType -eq 2 -or $cs.DomainRole -in 4,5) { return 'DC' }
        if ($os.ProductType -in 1,3 -and $cs.DomainRole -in 0,1,2,3) { return 'Local' }
    } catch {}
    return 'Unknown'
}

function Test-CPMutation {
    param([string]$What, [switch]$Recovery)
    if ($script:Dry) { Write-CP "[dry-run] $What" 'warn'; return $false }
    if ($Paranoid) { Write-CP "[paranoid] refused: $What" 'warn'; return $false }
    if ((Get-CPRole) -ne 'Local') { Write-CP "DC/unknown role: refused $What" 'warn'; return $false }
    if (-not $script:RecoveryMode -and -not $Recovery -and -not $script:BackupComplete -and -not (New-CPBackup)) {
        Write-CP "no verified backup: refused $What" 'err'
        return $false
    }
    return $true
}

# ReadOnly blocks may write private artifacts, never target configuration.
function Invoke-CP {
    param([string]$What, [scriptblock]$Block, [switch]$ReadOnly)
    if (-not $ReadOnly -and -not (Test-CPMutation $What)) { return $false }
    try {
        $ErrorActionPreference = 'Stop'
        & $Block | Out-Null
        Write-CP $What 'ok'
        return $true
    } catch {
        Add-Finding -Id 'OPERATION' -Area 'Execution' -Status 'WARN' -Detail ("{0}: {1}" -f $What, $_.Exception.Message)
        return $false
    }
}

function Invoke-CPNative {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$ArgumentList = @(),
        [int[]]$SuccessCodes = @(0),
        [switch]$ReadOnly
    )
    if (-not $ReadOnly -and -not (Test-CPMutation "$FilePath $($ArgumentList -join ' ')")) {
        throw 'native mutation refused'
    }
    if (-not [IO.Path]::IsPathRooted($FilePath)) {
        if (-not [IO.Path]::GetExtension($FilePath)) { $FilePath += '.exe' }
        $FilePath = Join-Path $env:SystemRoot ("System32\" + $FilePath)
    }
    $oldPreference = $ErrorActionPreference
    try {
        # Windows PowerShell can promote native stderr to an error before the
        # exit code is inspected. Both streams are captured, then the code wins.
        $ErrorActionPreference = 'Continue'
        $LASTEXITCODE = $null
        $output = @(& $FilePath @ArgumentList 2>&1)
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $oldPreference }
    if ($null -eq $code -or $SuccessCodes -notcontains $code) {
        throw ("{0} exited {1}: {2}" -f $FilePath, $code, ($output -join ' '))
    }
    $output | ForEach-Object { "$_" }
}

function Assert-CPNoReparse {
    param([Parameter(Mandatory)][string]$Path, [switch]$Trusted)
    if ($Path -notmatch '^[A-Za-z]:\\' -or $Path.Substring(2).Contains(':')) { throw "not a local absolute path: $Path" }
    $full = [IO.Path]::GetFullPath($Path)
    $current = $full
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "reparse point refused: $current" }
            if ($Trusted) {
                $acl = Get-Acl -LiteralPath $current -ErrorAction Stop
                $trustedSids = @('S-1-5-18','S-1-5-32-544', $script:IdentitySid,
                    'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
                if ($trustedSids -notcontains $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value) {
                    throw "untrusted artifact owner: $current"
                }
                $writeMask = [System.Security.AccessControl.FileSystemRights]'WriteData,WriteAttributes,WriteExtendedAttributes,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership'
                foreach ($ace in $acl.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier])) {
                    if ($ace.AccessControlType -ne 'Allow' -or ($ace.PropagationFlags -band 2)) { continue }
                    if ($trustedSids -notcontains $ace.IdentityReference.Value -and ($ace.FileSystemRights -band $writeMask)) {
                        throw "untrusted artifact write access: $current ($($ace.IdentityReference.Value))"
                    }
                }
            }
        }
        $parent = Split-Path -Path $current -Parent
        if ($parent -eq $current) { break }
        $current = $parent
    }
    return $full
}

function New-CPPrivateDirectory {
    param([Parameter(Mandatory)][string]$Path)
    $full = Assert-CPNoReparse $Path -Trusted
    if (-not (Test-Path -LiteralPath $full)) {
        $parent = Split-Path $full -Parent
        if (-not (Test-Path -LiteralPath $parent)) { New-CPPrivateDirectory $parent }
        $acl = New-Object System.Security.AccessControl.DirectorySecurity
        $acl.SetSecurityDescriptorSddlForm('O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
        # This overload sets the DACL at creation, before any secret is saved.
        [IO.Directory]::CreateDirectory($full, $acl) | Out-Null
    }
    $null = Assert-CPNoReparse $full -Trusted
}

function Initialize-CPArtifacts {
    $script:IdentitySid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $drive = New-Object IO.DriveInfo([IO.Path]::GetPathRoot($WorkRoot))
    if ($drive.DriveType -ne 'Fixed' -or $drive.DriveFormat -notin 'NTFS','ReFS') { throw 'artifacts require a local ACL-capable fixed volume' }
    $null = Assert-CPNoReparse $WorkRoot -Trusted
    if (Test-Path -LiteralPath $script:Root) { throw 'run directory already exists; refusing to reuse evidence' }
    foreach ($dir in @($script:Root,$script:EvidenceRoot,$script:BkDir,$script:Scratch)) { New-CPPrivateDirectory $dir }
    $script:ArtifactReady = $true
}

function Enter-CPPhase {
    param([string]$Name, [switch]$Mutating)
    if ($Mutating) {
        if ($Paranoid) { Write-CP "paranoid: $Name mutations skipped" 'warn'; return $false }
        if ((Get-CPRole) -ne 'Local') { Add-Review "$Name skipped: DC or unknown role"; return $false }
        if (-not $script:Dry -and -not (Test-CPMutation $Name)) { return $false }
    }
    $script:EvDir = Join-Path $script:EvidenceRoot ($Name + '-' + [guid]::NewGuid().ToString('N'))
    New-CPPrivateDirectory $script:EvDir
    return $true
}

function Register-Change {
    param([string]$What, [string]$Old, [string]$New)
    $script:Changed.Add([pscustomobject]@{ What=$What; Old=$Old; New=$New; Time=(Get-Date -Format 's') })
}

# ------------------------------------------------------------------------------
# file + registry helpers (backups before touching, old values recorded)
# ------------------------------------------------------------------------------
function Backup-CPFile {
    param([string]$Path)
    if (-not (Test-CPMutation "back up file before editing $Path")) { throw 'file change refused' }
    $full = Assert-CPNoReparse $Path
    $prior = @($script:FileJournal | Where-Object { $_.Path -ieq $full }) | Select-Object -First 1
    if ($prior) { return (Join-Path $script:BkDir $prior.Backup) }
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { throw "file not found: $full" }
    $relative = 'files\' + [guid]::NewGuid().ToString('N') + '.bak'
    $dest = Join-Path $script:BkDir $relative
    New-CPPrivateDirectory (Split-Path $dest -Parent)
    Copy-Item -LiteralPath $full -Destination $dest -ErrorAction Stop
    $hash = (Get-FileHash -LiteralPath $full -Algorithm SHA256 -ErrorAction Stop).Hash
    if ($hash -cne (Get-FileHash -LiteralPath $dest -Algorithm SHA256 -ErrorAction Stop).Hash) { throw 'file backup hash mismatch' }
    $script:FileJournal.Add([pscustomobject]@{ Path=$full; Backup=$relative; Hash=$hash })
    $script:FileJournal | Export-Clixml -LiteralPath (Join-Path $script:BkDir 'file-journal.clixml') -ErrorAction Stop
    return $dest
}

function Backup-RegKey {
    param([string]$Path)
    if ($script:Dry -or $Paranoid) { throw 'registry backup for mutation refused in read-only mode' }
    if (-not (Test-Path -LiteralPath $Path)) { return }
    if (@($script:RegExports | Where-Object { $_.Path -ieq $Path }).Count) { return }
    $native = $Path -replace '^HKLM:', 'HKLM' -replace '^HKCU:', 'HKCU'
    $relative = 'registry\' + [guid]::NewGuid().ToString('N') + '.reg'
    $dest = Join-Path $script:BkDir $relative
    New-CPPrivateDirectory (Split-Path $dest -Parent)
    Invoke-CPNative reg.exe @('export',$native,$dest) -ReadOnly | Out-Null
    if (-not (Test-Path -LiteralPath $dest) -or (Get-Item -LiteralPath $dest).Length -eq 0) { throw "empty registry export: $Path" }
    $script:RegExports.Add([pscustomobject]@{ Path=$Path; Backup=$relative; Hash=(Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash })
    $script:RegExports | Export-Clixml -LiteralPath (Join-Path $script:BkDir 'registry-exports.clixml') -ErrorAction Stop
}

function Get-CPReg {
    param([string]$Path, [string]$Name)
    try { return (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { return $null }
}

function Get-CPRegState {
    param([string]$Path, [string]$Name)
    $state = [pscustomobject]@{ KeyExists=$false; ValueExists=$false; Kind=''; Value=$null }
    if (Test-Path -LiteralPath $Path -ErrorAction Stop) {
        $key = Get-Item -LiteralPath $Path -ErrorAction Stop
        $state.KeyExists = $true
        if ($key.GetValueNames() -contains $Name) {
            $state.ValueExists = $true
            $state.Kind = $key.GetValueKind($Name).ToString()
            $state.Value = $key.GetValue($Name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        }
    }
    return $state
}

function Test-CPRegValue {
    param($Actual, $Expected, [string]$ActualType, [string]$ExpectedType)
    if ($ActualType -ine $ExpectedType -or $null -eq $Actual -or $null -eq $Expected) { return $false }
    if ($ExpectedType -in 'DWord','QWord') {
        try {
            if ($ExpectedType -eq 'DWord') { return (([long]$Actual -band 4294967295) -eq ([long]$Expected -band 4294967295)) }
            return ([decimal]$Actual -eq [decimal]$Expected)
        } catch { return $false }
    }
    if ($ExpectedType -in 'MultiString','Binary') {
        $left = @($Actual); $right = @($Expected)
        if ($left.Count -ne $right.Count) { return $false }
        for ($i = 0; $i -lt $left.Count; $i++) { if ($left[$i] -cne $right[$i]) { return $false } }
        return $true
    }
    return ($Actual -is [string] -and $Expected -is [string] -and $Actual -ceq $Expected)
}

function Save-CPRegUndo {
    param([string]$Path, [string]$Name, $State)
    if (@($script:RegJournal | Where-Object { $_.Path -ieq $Path -and $_.Name -ieq $Name }).Count) { return }
    Backup-RegKey $Path
    $missing = @()
    $parent = $Path
    while ($parent -and -not (Test-Path -LiteralPath $parent)) {
        $missing += $parent
        $parent = Split-Path $parent -Parent
    }
    $script:RegJournal.Add([pscustomobject]@{
        Path=$Path; Name=$Name; KeyExists=$State.KeyExists; ValueExists=$State.ValueExists
        Kind=$State.Kind; Value=$State.Value; CreatedKeys=$missing
    })
    $script:RegJournal | Export-Clixml -LiteralPath (Join-Path $script:BkDir 'registry-journal.clixml') -ErrorAction Stop
}

function Set-CPReg {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][AllowEmptyCollection()][AllowEmptyString()]$Value,
        [ValidateSet('DWord','QWord','String','ExpandString','MultiString','Binary')]
        [string]$Type = 'DWord',
        [string]$Id = '',
        [string]$Area = 'Registry'
    )
    if (-not (Test-CPMutation "reg $Path\$Name = $Value ($Type)")) { return $false }
    try {
        $old = Get-CPRegState $Path $Name
        if ($old.ValueExists -and (Test-CPRegValue $old.Value $Value $old.Kind $Type)) {
            if ($Id) { Add-Finding -Id $Id -Area $Area -Status 'PASS' -Detail "$Name already correct" }
            return $true
        }
        Save-CPRegUndo $Path $Name $old
        if (-not $old.KeyExists) { New-Item -Path $Path -Force -ErrorAction Stop | Out-Null }
        New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType $Type -Force -ErrorAction Stop | Out-Null
        $now = Get-CPRegState $Path $Name
        if (-not $now.ValueExists -or -not (Test-CPRegValue $now.Value $Value $now.Kind $Type)) { throw 'registry postcondition failed' }
        Register-Change -What ("$Path\$Name") -Old ("exists=$($old.ValueExists), type=$($old.Kind)") -New ("$Value ($Type)")
        if ($Id) { Add-Finding -Id $Id -Area $Area -Status 'PASS' -Detail "$Name set to $Value" }
        return $true
    } catch {
        if ($Id) {
            Add-Finding -Id $Id -Area $Area -Status 'WARN' `
                -Detail "could not set $Name : $($_.Exception.Message)" `
                -Hint 'Check key ownership, WOW6432Node, or a different value type.'
        }
        return $false
    }
}

function Remove-CPRegValue {
    param([string]$Path, [string]$Name)
    if (-not (Test-CPMutation "remove registry value $Path\$Name")) { return $false }
    $old = Get-CPRegState $Path $Name
    if (-not $old.ValueExists) { return $true }
    Save-CPRegUndo $Path $Name $old
    Remove-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
    if ((Get-CPRegState $Path $Name).ValueExists) { throw 'registry value removal failed' }
    Register-Change -What "$Path\$Name" -Old 'present (private typed backup)' -New 'absent'
    return $true
}

# ------------------------------------------------------------------------------
# service helpers.
# StartType is missing from Get-Service on older builds. Check CIM, then
# ServiceController; writes are checked and the resulting mode is verified.
# ------------------------------------------------------------------------------
function Get-CPStartType {
    param([string]$Name)
    try {
        $escaped = $Name -replace "'","''"
        $m = Get-CimInstance Win32_Service -Filter "Name='$escaped'" -ErrorAction Stop
        if ($m) {
            return $(switch ($m.StartMode) {
                'Auto'     { 'Automatic' }
                'Manual'   { 'Manual' }
                'Disabled' { 'Disabled' }
                default    { $m.StartMode }
            })
        }
    } catch {}
    try { return (Get-Service -Name $Name -ErrorAction Stop).StartType.ToString() } catch {}
    return 'Unknown'
}

function Set-CPStartType {
    param([string]$Name, [ValidateSet('Automatic','Manual','Disabled')][string]$Type)
    if (-not (Test-CPMutation "service $Name start type $Type")) { return $false }
    if ((Get-CPStartType $Name) -eq $Type) { return $true }
    Backup-RegKey "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    $scType = switch ($Type) { 'Automatic' {'auto'} 'Manual' {'demand'} 'Disabled' {'disabled'} }
    try { Invoke-CPNative sc.exe @('config',$Name,'start=',$scType) | Out-Null }
    catch { try { Set-Service -Name $Name -StartupType $Type -ErrorAction Stop } catch {} }
    if ((Get-CPStartType $Name) -eq $Type) { return $true }
    Write-CP "could not set '$Name' start type to $Type" 'warn'
    return $false
}

function Get-CPService {
    param([string]$Name)
    Get-Service -Name $Name -ErrorAction SilentlyContinue
}

# ------------------------------------------------------------------------------
# local account helpers (Get-LocalUser is missing on some old images)
# ------------------------------------------------------------------------------
function Get-CPUsers {
    if ((Get-CPRole) -ne 'Local') { Write-CP 'local account enumeration skipped on DC/unknown role' 'warn'; return @() }
    $out = @()
    try {
        foreach ($u in (Get-LocalUser -ErrorAction Stop)) {
            $out += [pscustomobject]@{
                Name             = $u.Name
                SID              = $u.SID.Value
                Enabled          = [bool]$u.Enabled
                PasswordRequired = [bool]$u.PasswordRequired
                PasswordLastSet  = $u.PasswordLastSet
                LastLogon        = $u.LastLogon
                PasswordExpires  = $u.PasswordExpires
                Description      = $u.Description
                Source           = 'Get-LocalUser'
            }
        }
        if ($out.Count -gt 0) { return $out }
    } catch { Write-CP 'Get-LocalUser unavailable, falling back to ADSI' 'info' }

    try {
        $adsi = [ADSI]"WinNT://$env:COMPUTERNAME"
        foreach ($o in $adsi.Children) {
            if ($o.SchemaClassName -ne 'User') { continue }
            $sidStr = ''
            try { $sidStr = (New-Object System.Security.Principal.SecurityIdentifier($o.objectSid,0)).Value } catch {}
            $disabled = $false;  try { $disabled = [bool]$o.AccountDisabled } catch {}
            $pwReq    = $true;   try { $pwReq    = [bool]$o.PasswordRequired } catch {}
            $out += [pscustomobject]@{
                Name=$o.Name; SID=$sidStr; Enabled=(-not $disabled)
                PasswordRequired=$pwReq; PasswordLastSet=$null; LastLogon=$null
                PasswordExpires=$null; Description=$o.Description; Source='ADSI'
            }
        }
    } catch { Write-CP ("ADSI enumeration failed: " + $_.Exception.Message) 'warn' }
    return $out
}

function Get-AdminMemberNames {
    # only LOCAL user accounts. domain members of the group are reported but
    # never touched -- demoting a domain admin from a member server is not
    # your call and can break the round.
    if ((Get-CPRole) -ne 'Local') { return @() }
    $local = @{}
    foreach ($u in @(Get-CPUsers)) { if ($u.SID) { $local[$u.SID] = $u.Name } }
    try {
        return @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop |
            Where-Object { $_.ObjectClass -eq 'User' -and $local.ContainsKey($_.SID.Value) } |
            ForEach-Object { $local[$_.SID.Value] })
    } catch {
        try {
            $sid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
            $name = ($sid.Translate([System.Security.Principal.NTAccount]).Value -split '\\')[-1]
            $group = [ADSI]("WinNT://$env:COMPUTERNAME/$name,group")
            $names = @()
            foreach ($member in @($group.psbase.Invoke('Members'))) {
                $bytes = $member.GetType().InvokeMember('objectSid','GetProperty',$null,$member,$null)
                $memberSid = (New-Object System.Security.Principal.SecurityIdentifier($bytes,0)).Value
                if ($local.ContainsKey($memberSid)) { $names += $local[$memberSid] }
            }
            return $names
        } catch { Add-Review 'could not verify local Administrators membership by SID; no name-parsing fallback'; return @() }
    }
}

# one name per line, '#' starts a comment. template created if missing.
function Read-List {
    param([string]$Path, [string]$Template)
    if (-not (Test-Path -LiteralPath $Path)) {
        if (-not (Test-CPMutation "create list template $Path")) { return @() }
        try {
            $null = Assert-CPNoReparse $Path
            Set-Content -LiteralPath $Path -Value $Template -ErrorAction Stop
        } catch { Write-CP "could not create list template: $($_.Exception.Message)" 'warn' }
        return @()
    }
    return @(Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue |
        ForEach-Object { ($_ -replace '#.*','').Trim() } | Where-Object { $_ })
}

# ------------------------------------------------------------------------------
# secedit helpers. we MERGE into the live policy instead of overwriting it,
# because /configure with a stock inf wipes user rights nobody remembers
# setting -- we broke a practice image that way once. never again.
# ------------------------------------------------------------------------------
function Get-SeceditInf {
    $tmp = Join-Path $script:Scratch ("policy-" + [guid]::NewGuid().ToString('N') + '.inf')
    Invoke-CPNative secedit.exe @('/export','/cfg',$tmp,'/areas','SECURITYPOLICY','USER_RIGHTS','REGKEYS','/log',($tmp + '.log'),'/quiet') -ReadOnly | Out-Null
    if (-not (Test-CPSeceditInf $tmp)) { throw 'secedit export missing, empty, or incomplete' }
    return $tmp
}

function Test-CPSeceditInf {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $false }
    $text = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    return ($text -match '(?im)^\s*\[Version\]\s*$' -and
            $text -match '(?im)^\s*\[System Access\]\s*$' -and
            $text -match '(?im)^\s*MinimumPasswordLength\s*=\s*\d+\s*$')
}

function Set-SeceditValue {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[string]]$Lines,
        [string]$Section, [string]$Key, [AllowEmptyString()][string]$Value,
        [switch]$Union, [switch]$PreserveStronger
    )
    $inSec = $false; $sectionIndex = -1; $insertIndex = $Lines.Count; $keyIndex = -1
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        $l = $Lines[$i].Trim()
        if ($l -match '^\[(.+)\]$') {
            if ($inSec) { $insertIndex = $i; break }
            $inSec = ($Matches[1] -ieq $Section)
            if ($inSec) { $sectionIndex = $i }
            continue
        }
        if ($inSec -and $l -match '^([^=]+)=(.*)$' -and $Matches[1].Trim() -ieq $Key) {
            $keyIndex = $i
            $old = $Matches[2].Trim()
            if ($Union) {
                $Value = (@(($old -split ',') + ($Value -split ',')) | ForEach-Object { $_.Trim() } |
                    Where-Object { $_ } | Select-Object -Unique) -join ','
            } elseif ($PreserveStronger) {
                $n = 0; $target = 0
                if ([int]::TryParse($old,[ref]$n) -and [int]::TryParse($Value,[ref]$target)) {
                    if ($Key -in 'MinimumPasswordLength','PasswordHistorySize','MinimumPasswordAge','ResetLockoutCount') {
                        $Value = [string][Math]::Max($n,$target)
                    } elseif ($Key -in 'MaximumPasswordAge','LockoutBadCount') {
                        if ($n -gt 0) { $Value = [string][Math]::Min($n,$target) }
                    } elseif ($Key -eq 'LockoutDuration') {
                        $Value = $(if ($n -eq 0) { '0' } else { [string][Math]::Max($n,$target) })
                    }
                }
            }
            break
        }
    }
    if ($keyIndex -ge 0) { $Lines[$keyIndex] = "$Key = $Value" }
    elseif ($sectionIndex -ge 0) { $Lines.Insert($insertIndex, "$Key = $Value") }
    else { $Lines.Add(''); $Lines.Add("[$Section]"); $Lines.Add("$Key = $Value") }
    return $true
}

function Apply-SeceditInf {
    param([string]$InfPath)
    if (-not (Test-CPMutation "secedit configure $InfPath")) { return $false }
    if (-not (Test-CPSeceditInf $InfPath)) { throw 'invalid security template' }
    Invoke-CPNative secedit.exe @('/validate',$InfPath) -ReadOnly | Out-Null
    $db = Join-Path $script:Scratch ('apply-' + [guid]::NewGuid().ToString('N') + '.sdb')
    try {
        Invoke-CPNative secedit.exe @('/configure','/db',$db,'/cfg',$InfPath,'/areas','SECURITYPOLICY','USER_RIGHTS','/log',($db + '.log'),'/quiet') | Out-Null
        return $true
    } catch { Write-CP $_.Exception.Message 'warn'; return $false }
}
# ------------------------------------------------------------------------------
# backup / restore
# ------------------------------------------------------------------------------
function New-CPBackup {
    if ($script:BackupComplete) { return $true }
    if ($script:Dry -or $NoBackup) { Write-CP 'backup skipped; mutations require a verified backup' 'warn'; return $false }
    if ($script:BackupAttempted) { Write-CP 'backup previously failed; start a new run rather than overwrite it' 'err'; return $false }
    $script:BackupAttempted = $true
    Write-Banner 'CONFIGURATION BACKUP'
    if (-not $script:ArtifactReady) { throw 'private artifacts not initialized' }
    New-CPPrivateDirectory $script:BkDir
    $b = $script:BkDir
    Write-CP "backup folder: $b"
    try {
        $machineGuid = Get-CPReg 'HKLM:\SOFTWARE\Microsoft\Cryptography' 'MachineGuid'
        if (-not $machineGuid) { throw 'cannot identify this Windows installation' }
        $manifest = [pscustomobject]@{
            Version=$script:Version; ComputerName=$env:COMPUTERNAME; MachineGuid=$machineGuid
            UserSid=$script:IdentitySid; Created=(Get-Date -Format 'o'); Complete=$false; Files=@()
        }
        $manifest | Export-Clixml -LiteralPath (Join-Path $b 'backup-manifest.clixml') -ErrorAction Stop
        foreach ($h in @('SOFTWARE','SYSTEM','SECURITY','SAM')) {
            Invoke-CPNative reg.exe @('save',"HKLM\$h",(Join-Path $b "$h.hiv")) -ReadOnly | Out-Null
        }
        Invoke-CPNative reg.exe @('export','HKCU\Software',(Join-Path $b 'HKCU-Software.reg')) -ReadOnly | Out-Null
        $policy = Get-SeceditInf
        Copy-Item -LiteralPath $policy -Destination (Join-Path $b 'secpol-before.inf') -ErrorAction Stop
        Invoke-CPNative netsh.exe @('advfirewall','export',(Join-Path $b 'firewall-before.wfw')) -ReadOnly | Out-Null
        Invoke-CPNative auditpol.exe @('/backup',('/file:' + (Join-Path $b 'audit-before.csv'))) -ReadOnly | Out-Null
        Invoke-CPNative net.exe @('user') -ReadOnly | Set-Content -LiteralPath (Join-Path $b 'net-user.txt') -ErrorAction Stop
        if ((Get-CPRole) -eq 'Local') {
            $localUsers = @(Get-CPUsers)
            if (-not $localUsers.Count) { throw 'local account backup is empty' }
            $localUsers | Export-Csv (Join-Path $b 'local-users.csv') -NoTypeInformation -ErrorAction Stop
            Invoke-CPNative net.exe @('localgroup') -ReadOnly | Set-Content -LiteralPath (Join-Path $b 'net-localgroup.txt') -ErrorAction Stop
            @(Get-AdminMemberNames) | Set-Content -LiteralPath (Join-Path $b 'local-administrators.txt') -ErrorAction Stop
        }
        $services = @(Get-CimInstance Win32_Service -ErrorAction Stop)
        if (-not $services.Count) { throw 'service backup is empty' }
        $services |
            Select-Object Name,DisplayName,State,StartMode,StartName,PathName |
            Export-Csv (Join-Path $b 'services.csv') -NoTypeInformation -ErrorAction Stop
        Invoke-CPNative schtasks.exe @('/query','/fo','LIST','/v') -ReadOnly | Set-Content -LiteralPath (Join-Path $b 'schtasks.txt') -ErrorAction Stop
        try { Get-SmbShare | Export-Csv (Join-Path $b 'shares.csv') -NoTypeInformation } catch {}
        Invoke-CPNative net.exe @('share') -ReadOnly | Set-Content -LiteralPath (Join-Path $b 'net-share.txt') -ErrorAction Stop
        Copy-Item -LiteralPath "$env:SystemRoot\System32\drivers\etc\hosts" -Destination (Join-Path $b 'hosts.txt') -ErrorAction Stop
        $paths = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                   'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
        Get-ItemProperty $paths -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } |
            Select-Object DisplayName,DisplayVersion,Publisher,InstallDate,UninstallString |
            Export-Csv (Join-Path $b 'programs.csv') -NoTypeInformation
        $logs = foreach ($log in @('Security','System','Application')) {
            Invoke-CPNative wevtutil.exe @('gl',$log,'/f:xml') -ReadOnly | Set-Content -LiteralPath (Join-Path $b ("event-$log.xml")) -ErrorAction Stop
            Get-WinEvent -ListLog $log -ErrorAction Stop | Select-Object LogName,MaximumSizeInBytes,LogMode,IsEnabled
        }
        $logs | Export-Clixml -LiteralPath (Join-Path $b 'eventlogs-before.clixml') -ErrorAction Stop
        if (Get-Command Get-MpPreference -ErrorAction SilentlyContinue) {
            Get-MpPreference -ErrorAction Stop | Export-Clixml -LiteralPath (Join-Path $b 'defender-before.clixml') -ErrorAction Stop
        }
        if (Get-Command Get-WindowsOptionalFeature -ErrorAction SilentlyContinue) {
            try { Get-WindowsOptionalFeature -Online -ErrorAction Stop | Export-Clixml -LiteralPath (Join-Path $b 'features-before.clixml') -ErrorAction Stop }
            catch { Add-Review "feature inventory unavailable: $($_.Exception.Message)" }
        }
        try { Invoke-CPNative gpresult.exe @('/h',(Join-Path $b 'gpresult.html')) -ReadOnly | Out-Null }
        catch { Add-Review "group policy report unavailable: $($_.Exception.Message)" }
        $required = @('SOFTWARE.hiv','SYSTEM.hiv','SECURITY.hiv','SAM.hiv','HKCU-Software.reg',
            'secpol-before.inf','firewall-before.wfw','audit-before.csv','services.csv','eventlogs-before.clixml','hosts.txt')
        foreach ($name in $required) {
            $file = Get-Item -LiteralPath (Join-Path $b $name) -ErrorAction Stop
            if (-not $file.Length) { throw "empty required backup: $name" }
        }
        $manifest.Files = @(Get-ChildItem -LiteralPath $b -File -ErrorAction Stop |
            Where-Object { $_.Name -ne 'backup-manifest.clixml' } | ForEach-Object {
                [pscustomobject]@{ Backup=$_.Name; Hash=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256 -ErrorAction Stop).Hash }
            })
        $manifest.Complete = $true
        $manifest | Export-Clixml -LiteralPath (Join-Path $b 'backup-manifest.clixml') -ErrorAction Stop
        $script:BackupComplete = $true
        Write-CP 'configuration backup verified; account deletion/password changes are not undoable' 'ok'
        return $true
    } catch {
        Add-Finding -Id 'BACKUP' -Area 'Recovery' -Status 'FAIL' -Detail $_.Exception.Message -Hint 'All mutations are blocked. Keep this partial backup and start a new run after fixing the failure.'
        return $false
    }
}

function Restore-CPBackup {
    param([string]$Path)
    if (-not (Test-CPMutation 'configuration recovery' -Recovery)) { return }
    $Path = Assert-CPNoReparse $Path -Trusted
    $manifest = Import-Clixml -LiteralPath (Join-Path $Path 'backup-manifest.clixml') -ErrorAction Stop
    if (-not $manifest.Complete -or $manifest.Version -ne '1.3.0' -or
        $manifest.ComputerName -ine $env:COMPUTERNAME -or
        $manifest.MachineGuid -cne (Get-CPReg 'HKLM:\SOFTWARE\Microsoft\Cryptography' 'MachineGuid')) {
        throw 'backup incomplete, unsupported, or belongs to another Windows installation'
    }
    foreach ($entry in @($manifest.Files)) {
        $file = Join-Path $Path $entry.Backup
        $null = Assert-CPNoReparse $file -Trusted
        if ((Get-FileHash -LiteralPath $file -Algorithm SHA256 -ErrorAction Stop).Hash -cne $entry.Hash) { throw "backup hash mismatch: $file" }
    }
    Write-Banner "RESTORE FROM $Path"
    if (-not (Confirm-CP 'Recover saved configuration on this machine? This is NOT password/account/data recovery.')) { return }
    $script:RecoveryMode = $true
    Invoke-CP 'restore secpol' {
        if (-not (Apply-SeceditInf (Join-Path $Path 'secpol-before.inf'))) { throw 'security policy recovery failed' }
    } | Out-Null
    Invoke-CP 'restore firewall' {
        Invoke-CPNative netsh.exe @('advfirewall','import',(Join-Path $Path 'firewall-before.wfw')) | Out-Null
    } | Out-Null
    Invoke-CP 'restore audit policy' {
        Invoke-CPNative auditpol.exe @('/restore',('/file:' + (Join-Path $Path 'audit-before.csv'))) | Out-Null
    } | Out-Null
    Invoke-CP 'restore per-key exports and typed registry journal' {
        $exports = Join-Path $Path 'registry-exports.clixml'
        if (Test-Path -LiteralPath $exports) {
            foreach ($entry in @(Import-Clixml -LiteralPath $exports -ErrorAction Stop)) {
                if ($entry.Path -notmatch '^HK(LM|CU):\\') { throw 'unsupported registry backup path' }
                if ($entry.Path -like 'HKCU:*' -and $manifest.UserSid -ne $script:IdentitySid) { throw 'HKCU recovery requires the original user SID' }
                $file = Join-Path $Path $entry.Backup
                $null = Assert-CPNoReparse $file -Trusted
                if ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -cne $entry.Hash) { throw 'registry export hash mismatch' }
                Backup-RegKey $entry.Path
                Invoke-CPNative reg.exe @('import',$file) | Out-Null
            }
        }
        $journal = Join-Path $Path 'registry-journal.clixml'
        if (Test-Path -LiteralPath $journal) {
            $entries = @(Import-Clixml -LiteralPath $journal -ErrorAction Stop)
            [array]::Reverse($entries)
            foreach ($entry in $entries) {
                if ($entry.Path -notmatch '^HK(LM|CU):\\') { throw 'unsupported registry journal path' }
                if ($entry.Path -like 'HKCU:*' -and $manifest.UserSid -ne $script:IdentitySid) { throw 'HKCU recovery requires the original user SID' }
                if ($entry.ValueExists) {
                    if (-not (Set-CPReg $entry.Path $entry.Name $entry.Value $entry.Kind)) { throw 'typed registry recovery failed' }
                } else {
                    if (-not (Remove-CPRegValue $entry.Path $entry.Name)) { throw 'registry removal recovery failed' }
                    foreach ($keyPath in @($entry.CreatedKeys)) {
                        if (Test-Path -LiteralPath $keyPath) {
                            $key = Get-Item -LiteralPath $keyPath -ErrorAction Stop
                            if ($key.ValueCount -eq 0 -and $key.SubKeyCount -eq 0) { Remove-Item -LiteralPath $keyPath -ErrorAction Stop }
                        }
                    }
                }
            }
        }
    } | Out-Null
    Invoke-CP 'restore saved file configurations' {
        $journal = Join-Path $Path 'file-journal.clixml'
        if (Test-Path -LiteralPath $journal) {
            foreach ($entry in @(Import-Clixml -LiteralPath $journal -ErrorAction Stop)) {
                $file = Join-Path $Path $entry.Backup
                $null = Assert-CPNoReparse $file -Trusted
                $null = Assert-CPNoReparse $entry.Path
                if ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -cne $entry.Hash) { throw 'file recovery hash mismatch' }
                Backup-CPFile $entry.Path | Out-Null
                Copy-Item -LiteralPath $file -Destination $entry.Path -Force -ErrorAction Stop
                if ((Get-FileHash -LiteralPath $entry.Path -Algorithm SHA256).Hash -cne $entry.Hash) { throw 'file recovery postcondition failed' }
            }
        }
    } | Out-Null
    Invoke-CP 'restore changed service modes and state' {
        $exports = Join-Path $Path 'registry-exports.clixml'
        $changedServices = @()
        if (Test-Path -LiteralPath $exports) {
            $changedServices = @(Import-Clixml -LiteralPath $exports | Where-Object { $_.Path -match '^HKLM:\\SYSTEM\\CurrentControlSet\\Services\\[^\\]+$' } |
                ForEach-Object { Split-Path $_.Path -Leaf })
        }
        foreach ($svc in @(Import-Csv -LiteralPath (Join-Path $Path 'services.csv'))) {
            if ($changedServices -notcontains $svc.Name) { continue }
            $mode = switch ($svc.StartMode) { 'Auto' { 'Automatic' } 'Manual' { 'Manual' } 'Disabled' { 'Disabled' } default { throw 'unknown saved service mode' } }
            if (-not (Set-CPStartType $svc.Name $mode)) { throw "service mode recovery failed: $($svc.Name)" }
            if ($svc.State -eq 'Running') { Start-Service -Name $svc.Name -ErrorAction Stop }
            elseif ($svc.State -eq 'Stopped') { Stop-Service -Name $svc.Name -ErrorAction Stop }
        }
    } | Out-Null
    Invoke-CP 'restore event log sizes and rotation modes' {
        foreach ($log in @(Import-Clixml -LiteralPath (Join-Path $Path 'eventlogs-before.clixml'))) {
            $retention = if ($log.LogMode -eq 'Circular') { 'false' } else { 'true' }
            $archive = if ($log.LogMode -eq 'AutoBackup') { 'true' } else { 'false' }
            Invoke-CPNative wevtutil.exe @('sl',$log.LogName,("/ms:" + $log.MaximumSizeInBytes),("/rt:$retention"),("/ab:$archive")) | Out-Null
        }
    } | Out-Null
    if ($AdvancedHiveRestore -and (Confirm-CP 'ADVANCED: attempt raw live SOFTWARE/SYSTEM/SECURITY/SAM recovery? This may fail or make Windows unbootable. Prefer offline recovery.' -InteractiveOnly)) {
        Invoke-CP 'advanced raw hive recovery' {
            foreach ($h in @('SOFTWARE','SYSTEM','SECURITY','SAM')) {
                Invoke-CPNative reg.exe @('restore',"HKLM\$h",(Join-Path $Path "$h.hiv")) | Out-Null
            }
        } | Out-Null
    }
    Add-Review 'Configuration recovery attempted; review each result, Defender preferences/features/accounts and global resource SACLs manually. Verify workloads and reboot as appropriate. Passwords, deletions and firmware are not undone.'
}

# ------------------------------------------------------------------------------
# README / scenario finder -- the highest-value two minutes of the round
# ------------------------------------------------------------------------------
function Get-CPReadme {
    Write-Banner 'README / SCENARIO'
    $roots = @('C:\', "$env:USERPROFILE\Desktop", "$env:USERPROFILE\Documents",
               'C:\Users', 'C:\ProgramData', 'C:\inetpub')
    $nameHits = @('readme','read me','instructions','scenario','notes','todo','task',
                  'welcome','company','policy','policies','audit','important','memo','breach')
    $found = @()
    foreach ($r in $roots) {
        if (-not (Test-Path $r)) { continue }
        try {
            foreach ($f in (Get-ChildItem -Path $r -Recurse -Depth 3 -File -ErrorAction SilentlyContinue)) {
                if ($f.Extension -notin '.txt','.md','.rtf','.doc','.docx','.pdf') { continue }
                if ($f.Length -gt 512KB) { continue }      # a readme is never 512KB
                if ($f.FullName -match '(?i)\\AppData\\|\\Windows\\|\\Program Files') { continue }
                $low = $f.Name.ToLower()
                $hit = $false
                foreach ($n in $nameHits) { if ($low.Contains($n)) { $hit = $true; break } }
                if ($hit) { $found += $f }
            }
        } catch {}
    }
    $found = @($found | Sort-Object FullName -Unique)

    if ($found.Count -eq 0) {
        Write-CP 'no readme-looking file found. CHECK EVERY DESKTOP AND C:\ BY HAND.' 'warn'
        Add-Finding -Id 'README-LOCATE' -Area 'Scenario' -Status 'WARN' -Detail 'no README found automatically' `
            -Hint 'Look on every user desktop, C:\, C:\ProgramData, and the Recycle Bin. The README lists authorized users and critical services -- it is worth more than any registry key.'
        return
    }

    $out = Join-Path $script:EvDir 'readme-candidates.txt'
    New-Item -ItemType Directory -Path $script:EvDir -Force -ErrorAction SilentlyContinue | Out-Null
    $found | Select-Object FullName,Length,LastWriteTime | Format-Table -Auto | Out-String | Set-Content $out
    Write-CP ("candidate README files: {0}  (list at {1})" -f $found.Count, $out) 'ok'

    foreach ($f in $found) {
        Write-Host ('-' * 78) -ForegroundColor DarkGray
        Write-Host (" FILE: {0}   ({1} bytes, modified {2})" -f $f.FullName, $f.Length, $f.LastWriteTime) -ForegroundColor White
        Write-Host ('-' * 78) -ForegroundColor DarkGray
        if ($f.Extension -in '.txt','.md') {
            try {
                $body = @(Get-Content $f.FullName -ErrorAction Stop)
                $body | Select-Object -First 120 | ForEach-Object { Write-Host ("   " + $_) }
                if ($body.Count -gt 120) { Write-Host '   ...truncated...' -ForegroundColor DarkGray }
                Add-Content $out ("`n===== " + $f.FullName + " =====`n" + ($body -join "`r`n"))
            } catch { Write-CP ("could not read: " + $_.Exception.Message) 'warn' }
        } else {
            Write-CP '   binary/doc format -- open it by hand.' 'info'
        }
    }
    Write-Host ''
    Write-CP 'ACTION: write down (1) authorized users, (2) critical services, (3) business/PII files, (4) every explicit task. Those are scored.' 'warn'
    Add-Finding -Id 'README-READ' -Area 'Scenario' -Status 'INFO' -Detail "$($found.Count) candidate file(s) dumped" `
        -Hint 'Everything the README asks for is a guaranteed point if you actually do it. Most teams skim it and lose the easiest points on the image.'
}
# ------------------------------------------------------------------------------
# recon / evidence dump. read only. this is the raw material for the
# forensic questions -- collect it BEFORE hardening rotates anything.
# ------------------------------------------------------------------------------
function Invoke-Recon {
    Write-Banner 'RECON + EVIDENCE'
    if (-not (Enter-CPPhase 'recon')) { return }
    $ev = $script:EvDir
    Write-CP "evidence -> $ev"

    Invoke-CP -ReadOnly 'system summary' {
        $os = Get-CimInstance Win32_OperatingSystem
        $cs = Get-CimInstance Win32_ComputerSystem
        $av = (Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue).displayName
        @(
            "hostname    : $env:COMPUTERNAME"
            "run as      : $env:USERNAME"
            "started     : $(Get-Date -Format s)"
            "OS          : $($os.Caption)"
            "version     : $($os.Version)"
            "install date: $($os.InstallDate)"
            "last boot   : $($os.LastBootUpTime)"
            "domain/role : $($cs.Domain) / PartOfDomain=$($cs.PartOfDomain) / ProductType=$($os.ProductType)"
            "AV product  : $av"
        ) | Set-Content (Join-Path $ev '00-summary.txt')
        Get-Content (Join-Path $ev '00-summary.txt') | ForEach-Object { Write-Host ("   " + $_) }
    }

    Get-CPReadme

    # ---- accounts -------------------------------------------------------
    Invoke-CP -ReadOnly 'local accounts' {
        $rows = @(Get-CPUsers)
        $rows | Export-Csv (Join-Path $ev '10-users.csv') -NoTypeInformation
        $rows | Format-Table Name,Enabled,PasswordRequired,PasswordLastSet,LastLogon,SID -Auto |
            Out-String -Width 220 | Set-Content (Join-Path $ev '10-users.txt')
        Get-Content (Join-Path $ev '10-users.txt') | ForEach-Object { Write-Host ("   " + $_) }

        try {
            $gm = @{}
            foreach ($grp in (Get-LocalGroup -ErrorAction Stop)) {
                foreach ($m in (Get-LocalGroupMember -Group $grp.Name -ErrorAction SilentlyContinue)) {
                    if (-not $gm.ContainsKey($m.Name)) { $gm[$m.Name] = New-Object System.Collections.ArrayList }
                    $null = $gm[$m.Name].Add($grp.Name)
                }
            }
            $lines = @()
            foreach ($k in $gm.Keys) { $lines += ("  {0}: {1}" -f $k, ($gm[$k] -join ', ')) }
            Add-Content (Join-Path $ev '10-users.txt') "`n--- group membership ---"
            Add-Content (Join-Path $ev '10-users.txt') $lines
        } catch {}

        foreach ($u in $rows) {
            if ($u.Name -ieq 'guest') {
                Add-Finding -Id 'USER-Guest' -Area 'Accounts' -Status $(if ($u.Enabled) {'FAIL'} else {'PASS'}) `
                    -Detail "guest account enabled=$($u.Enabled)" -Hint 'Guest should be disabled. Do NOT delete it.'
            }
            if ((-not $u.PasswordRequired) -and $u.Enabled) {
                Add-Finding -Id "USER-$($u.Name)" -Area 'Accounts' -Status 'FAIL' `
                    -Detail "$($u.Name) has no password required" -Hint 'Blank password = almost always a scored vuln. Fix it in the users section.'
            }
            if ($u.PasswordExpires -eq $false -and $u.Enabled) {
                Add-Finding -Id "USER-$($u.Name)" -Area 'Accounts' -Status 'WARN' `
                    -Detail "$($u.Name) password never expires" -Hint 'Frequently scored. Fix unless the README calls it a service account.'
            }
            if ($u.PasswordLastSet) {
                try {
                    if ([datetime]$u.PasswordLastSet -lt (Get-Date).AddYears(-1) -and $u.Enabled) {
                        Add-Finding -Id "USER-$($u.Name)" -Area 'Accounts' -Status 'WARN' `
                            -Detail "$($u.Name) password last set $([datetime]$u.PasswordLastSet)" -Hint 'Stale password. Check max age policy.'
                    }
                } catch {}
            }
            # Renaming the built-in administrator is normal; its SID is stable.
            if ($u.SID -and $u.SID -match '-500$' -and $u.Name -ne 'Administrator') {
                Add-Finding -Id "USER-RID500-$($u.Name)" -Area 'Accounts' -Status 'INFO' `
                    -Detail "$($u.Name) holds RID 500 (the built-in admin RID)" `
                    -Hint 'A renamed RID-500 account is not proof of a clone. Compare verified SIDs and account history.'
            }
        }

        # hidden accounts: visible to WMI but not to Get-LocalUser
        try {
            $names = @($rows | ForEach-Object { $_.Name })
            $cls = @(Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction Stop | ForEach-Object { $_.Name })
            $hidden = @($cls | Where-Object { $_ -and ($names -notcontains $_) })
            if ($hidden.Count -gt 0) {
                Add-Finding -Id 'USER-HIDDEN' -Area 'Accounts' -Status 'FAIL' -Detail "hidden account(s): $($hidden -join ', ')" `
                    -Hint 'Accounts present in WMI but not Get-LocalUser (names ending in $ are normal) are a classic backdoor. Report + disable, do not delete.'
            } else {
                Add-Finding -Id 'USER-HIDDEN' -Area 'Accounts' -Status 'PASS' -Detail 'no hidden local accounts'
            }
        } catch {
            Add-Finding -Id 'USER-HIDDEN-ERROR' -Area 'Accounts' -Status 'WARN' -Detail 'could not compare WMI and local account lists' `
                -Hint 'Run: Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True"; do not assume there are no hidden accounts.'
        }
    }

    Invoke-CP -ReadOnly 'group membership' {
        $g = @()
        foreach ($grp in @('Administrators','Users','Guests','Remote Desktop Users','Power Users',
                           'Backup Operators','Account Operators','Print Operators','Server Operators',
                           'Replicators','Cryptographic Operators','Network Configuration Operators',
                           'Distributed COM Users','Event Log Readers','Hyper-V Administrators',
                           'IIS_IUSRS','Performance Log Users')) {
            try {
                $m = @(Get-LocalGroupMember -Group $grp -ErrorAction Stop)
                foreach ($x in $m) {
                    $g += [pscustomobject]@{ Group=$grp; Member=$x.Name; SID=$x.SID.Value; Type=$x.ObjectClass }
                }
                if ($m.Count -gt 0 -and $grp -notin @('Users','Guests','Administrators','IIS_IUSRS')) {
                    Add-Finding -Id "GRP-$grp" -Area 'Accounts' -Status 'WARN' `
                        -Detail "$grp has $($m.Count) member(s): $(($m | ForEach-Object { $_.Name }) -join ', ')" `
                        -Hint 'Privileged group with members -- verify each against the README authorized-user list.'
                }
            } catch {}
        }
        $g | Export-Csv (Join-Path $ev '11-groups.csv') -NoTypeInformation
    }

    # ---- network --------------------------------------------------------
    Invoke-CP -ReadOnly 'listening ports' {
        $rows = @()
        try {
            foreach ($x in (Get-NetTCPConnection -State Listen -ErrorAction Stop)) {
                $procName = ''
                try { $procName = (Get-Process -Id $x.OwningProcess -ErrorAction Stop).ProcessName } catch {}
                $rows += [pscustomobject]@{ Proto='TCP'; LocalAddress=$x.LocalAddress; Port=$x.LocalPort; PID=$x.OwningProcess; Process=$procName }
            }
        } catch {
            # Get-NetTCPConnection missing on some old images -> parse netstat
            foreach ($line in (Invoke-CPNative netstat.exe @('-ano') -ReadOnly)) {
                if ("$line" -notmatch 'LISTENING') { continue }
                $bits = @("$line" -split '\s+' | Where-Object { $_ })
                if ($bits.Count -lt 5) { continue }
                $la = $bits[1]
                $lp = 0
                if ($la.LastIndexOf(':') -gt 0) { [void][int]::TryParse($la.Substring($la.LastIndexOf(':')+1), [ref]$lp) }
                $pn = ''
                try { $pn = (Get-Process -Id $bits[4] -ErrorAction Stop).ProcessName } catch {}
                $rows += [pscustomobject]@{ Proto='TCP'; LocalAddress=$la; Port=$lp; PID=$bits[4]; Process=$pn }
            }
        }
        $rows | Sort-Object Port -Unique | Export-Csv (Join-Path $ev '20-listening.csv') -NoTypeInformation
        $rows | Sort-Object Port -Unique | Format-Table -Auto | Out-String -Width 200 | Set-Content (Join-Path $ev '20-listening.txt')
        Invoke-CPNative netstat.exe @('-anob') -ReadOnly | Set-Content (Join-Path $ev '20-netstat-anob.txt')
        Get-Content (Join-Path $ev '20-listening.txt') | ForEach-Object { Write-Host ("   " + $_) }

        $badPorts = @{
            21='FTP'; 23='Telnet'; 69='TFTP'; 135='RPC'; 139='NetBIOS-SSN'; 445='SMB';
            1433='MSSQL'; 3306='MySQL'; 3389='RDP'; 5900='VNC'; 5985='WinRM'; 5986='WinRM-S';
            8080='alt-http'; 4444='common-backdoor'; 31337='common-backdoor'; 6667='IRC';
            11211='memcached'; 27017='MongoDB'; 5432='PostgreSQL'; 9200='Elasticsearch'
        }
        foreach ($r in $rows) {
            $p = 0
            if ([int]::TryParse("$($r.Port)", [ref]$p) -and $badPorts.ContainsKey($p)) {
                Add-Finding -Id "PORT-$p" -Area 'Network' -Status $(if ($p -in 23,4444,31337,6667,5900) {'FAIL'} else {'WARN'}) `
                    -Detail "$p/tcp open ($($badPorts[$p]) -> $($r.Process))" `
                    -Hint 'Is this a critical service from the README? If not, stop+disable the service AND block the port. Do both or neither.'
            }
        }
    }

    # ---- persistence ----------------------------------------------------
    Invoke-CP -ReadOnly 'persistence: run keys + winlogon' {
        $keys = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
            'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
            'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        )
        $dump = @()
        foreach ($k in $keys) {
            if (-not (Test-Path $k)) { continue }
            $p = Get-ItemProperty $k
            foreach ($n in ($p.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' })) {
                $dump += [pscustomobject]@{ Key=$k; Name=$n.Name; Value=$n.Value }
                if ($k -like '*Winlogon*' -and $n.Name -match '^(Shell|Userinit|System)$') {
                    $bad = $false
                    if ($n.Name -eq 'Shell'     -and "$($n.Value)" -notmatch '(?i)^explorer\.exe$') { $bad = $true }
                    if ($n.Name -eq 'Userinit'  -and "$($n.Value)" -notmatch '(?i)^C:\\Windows\\system32\\userinit\.exe,?$') { $bad = $true }
                    if ($n.Name -eq 'System') { $bad = $true }
                    if ($bad) {
                        Add-Finding -Id "RUN-$($n.Name)" -Area 'Persistence' -Status 'FAIL' -Detail "Winlogon $($n.Name) = $($n.Value)" `
                            -Hint 'Shell must be exactly explorer.exe, Userinit exactly C:\Windows\system32\userinit.exe, and System should not exist.'
                    }
                }
                if ("$($n.Value)" -match '(?i)\\temp\\|\\appdata\\|powershell|-enc\b|cmd\.exe /c|wscript|cscript|mshta|\.vbs|\.bat|\.js\b|certutil|bitsadmin|rundll32') {
                    Add-Finding -Id "RUN-$($n.Name)" -Area 'Persistence' -Status 'FAIL' -Detail "suspicious autorun: $($n.Name) = $($n.Value)" `
                        -Hint 'Autorun pointing at temp/appdata/a script host = malware persistence. Screenshot it, remove the value, note it in the report.'
                }
            }
        }
        $dump | Export-Csv (Join-Path $ev '30-run-keys.csv') -NoTypeInformation
    }

    Invoke-CP -ReadOnly 'persistence: IFEO debugger hijacks' {
        # the classic "press shift 5 times -> cmd.exe" trick lives here
        $ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
        $hits = @()
        if (Test-Path $ifeo) {
            foreach ($sub in (Get-ChildItem $ifeo -ErrorAction Stop)) {
                $dbg = Get-CPReg -Path $sub.PSPath -Name 'Debugger'
                if ($dbg) {
                    $hits += [pscustomobject]@{ Target=$sub.PSChildName; Debugger=$dbg }
                    Add-Finding -Id "IFEO-$($sub.PSChildName)" -Area 'Persistence' -Status 'FAIL' `
                        -Detail "IFEO hijack: $($sub.PSChildName) launches '$dbg'" `
                        -Hint 'A Debugger value on sethc.exe/utilman/osk/narrator means that key launches a shell. Delete the Debugger value.'
                }
            }
        }
        $hits | Export-Csv (Join-Path $ev '31-ifeo.csv') -NoTypeInformation
        if ($hits.Count -eq 0) { Add-Finding -Id 'IFEO' -Area 'Persistence' -Status 'PASS' -Detail 'no IFEO debugger hijacks' }
    }

    Invoke-CP -ReadOnly 'persistence: sticky keys + accessibility binaries' {
        foreach ($bin in @('sethc.exe','utilman.exe','osk.exe','narrator.exe','Magnify.exe')) {
            $path = "C:\Windows\System32\$bin"
            if (-not (Test-Path $path)) { continue }
            try {
                $sig = Get-AuthenticodeSignature $path -ErrorAction Stop
                if ($sig.Status -ne 'Valid') {
                    Add-Finding -Id "STICKY-$bin" -Area 'Persistence' -Status 'FAIL' `
                        -Detail "$bin is NOT signed ($($sig.Status))" `
                        -Hint 'A replaced accessibility binary is the textbook Windows backdoor. Hash it, report it, restore from a clean copy if you can.'
                }
            } catch {}
        }
    }

    Invoke-CP -ReadOnly 'persistence: startup folders' {
        $sf = @(
            "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
            "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
        )
        foreach ($u in (Get-ChildItem C:\Users -Directory -ErrorAction SilentlyContinue)) {
            $sf += (Join-Path $u.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup')
        }
        foreach ($d in $sf) {
            if (-not (Test-Path $d)) { continue }
            foreach ($i in @(Get-ChildItem $d -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' })) {
                Add-Finding -Id "STARTUP-$($i.Name)" -Area 'Persistence' -Status 'WARN' -Detail "startup item: $($i.FullName)" `
                    -Hint 'Anything in a Startup folder that the README does not mention is suspect. Check the target, hash it, then remove it.'
            }
        }
    }

    Invoke-CP -ReadOnly 'persistence: scheduled tasks' {
        $rows = @()
        try {
            foreach ($x in (Get-ScheduledTask -ErrorAction Stop)) {
                if ($x.State -eq 'Disabled') { continue }
                if ($x.TaskPath -like '\Microsoft\*') { continue }
                $rows += [pscustomobject]@{
                    Path=$x.TaskPath; Name=$x.TaskName; State=$x.State
                    Actions=(($x.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' | ')
                }
            }
        } catch {}
        $rows | Export-Csv (Join-Path $ev '32-tasks.csv') -NoTypeInformation
        foreach ($r in $rows) {
            if ($r.Actions -match '(?i)\\temp\\|\\appdata\\|powershell|-enc\b|mshta|wscript|cscript|\.vbs|\.bat|certutil|bitsadmin|rundll32|\\programdata\\') {
                Add-Finding -Id "TASK-$($r.Name)" -Area 'Persistence' -Status 'FAIL' -Detail "$($r.Path)$($r.Name) -> $($r.Actions)" `
                    -Hint 'Non-Microsoft task running a script host or a temp binary. Disable-ScheduledTask it and document it.'
            } elseif ($r.Path -notlike '\Microsoft\*') {
                Add-Finding -Id "TASK-$($r.Name)" -Area 'Persistence' -Status 'INFO' -Detail "non-Microsoft task: $($r.Path)$($r.Name) -> $($r.Actions)"
            }
        }
    }

    Invoke-CP -ReadOnly 'persistence: services with odd binPaths' {
        $s = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue)
        $s | Select-Object Name,DisplayName,State,StartMode,StartName,PathName |
            Export-Csv (Join-Path $ev '33-services.csv') -NoTypeInformation
        foreach ($x in $s) {
            if ($x.PathName -match '(?i)\\temp\\|\\appdata\\|\\programdata\\|\\users\\public\\|\\downloads\\|powershell|cmd\.exe|wscript|mshta') {
                Add-Finding -Id "SVC-$($x.Name)" -Area 'Persistence' -Status 'FAIL' -Detail "$($x.Name) -> $($x.PathName)" `
                    -Hint 'Service binary outside Program Files / Windows is a strong malware indicator. Hash it, report it, disable it.'
            }
            if ($x.StartName -and $x.StartName -notmatch '(?i)^(localsystem|localservice|networkservice|nt authority|nt service|\.\\)') {
                Add-Finding -Id "SVC-$($x.Name)" -Area 'Services' -Status 'WARN' -Detail "$($x.Name) runs as $($x.StartName)" `
                    -Hint 'Service running under a named local account is often a scored finding. Verify against the README.'
            }
        }
    }

    Invoke-CP -ReadOnly 'persistence: WMI event subscriptions' {
        $filt = @(Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction Stop)
        $cons = @(Get-WmiObject -Namespace root\subscription -Class __EventConsumer -ErrorAction Stop)
        $filt | Export-Csv (Join-Path $ev '34-wmi-filters.csv') -NoTypeInformation
        $cons | Export-Csv (Join-Path $ev '34-wmi-consumers.csv') -NoTypeInformation
        if ($filt.Count -gt 0 -or $cons.Count -gt 0) {
            Add-Finding -Id 'WMI-PERSIST' -Area 'Persistence' -Status 'WARN' -Detail "$($filt.Count) event filter(s), $($cons.Count) consumer(s)" `
                -Hint 'WMI event subscription is a stealthy persistence mechanism. Inspect each and remove what the README does not explain.'
        } else {
            Add-Finding -Id 'WMI-PERSIST' -Area 'Persistence' -Status 'PASS' -Detail 'no WMI event subscriptions'
        }
    }

    # ---- malware hunt ----------------------------------------------------
    Invoke-CP -ReadOnly 'malware hunt: processes + sketchy locations' {
        Get-Process | Sort-Object CPU -Descending |
            Select-Object -First 15 Name,Id,CPU,Path | Format-Table -Auto |
            Out-String -Width 220 | Set-Content (Join-Path $ev '35-top-processes.txt')
        Get-Content (Join-Path $ev '35-top-processes.txt') | ForEach-Object { Write-Host ("   " + $_) }

        # round "malware" is usually fake and AV misses it. the binary lives
        # somewhere writable -- temp, appdata, public, downloads. that is the
        # whole list of hiding places that matter.
        $sketchy = @("$env:TEMP", 'C:\Windows\Temp', 'C:\Users\Public', "$env:APPDATA", "$env:LOCALAPPDATA\Temp")
        $found = @()
        foreach ($d in $sketchy) {
            $found += @(Get-ChildItem $d -Recurse -Include *.exe,*.bat,*.cmd,*.vbs,*.ps1,*.js,*.jar -ErrorAction SilentlyContinue |
                Select-Object FullName,Length,LastWriteTime)
        }
        $found | Export-Csv (Join-Path $ev '36-sketchy-binaries.csv') -NoTypeInformation
        if ($found.Count -gt 0) {
            Add-Finding -Id 'MAL-SKETCHY' -Area 'Malware' -Status 'WARN' -Detail "$($found.Count) executable(s)/script(s) in temp/appdata/public" `
                -Hint 'Round malware usually hides exactly here. Kill the process, delete the file, THEN remove its persistence (run keys / startup / tasks).'
        } else {
            Add-Finding -Id 'MAL-SKETCHY' -Area 'Malware' -Status 'PASS' -Detail 'nothing executable in the usual hiding spots'
        }
    }

    # ---- shares ----------------------------------------------------------
    Invoke-CP -ReadOnly 'shares and share ACLs' {
        $sh = @()
        try { $sh = @(Get-SmbShare -ErrorAction Stop) } catch {}
        $sh | Export-Csv (Join-Path $ev '40-shares.csv') -NoTypeInformation
        $aclAll = @()
        foreach ($s in $sh) {
            $acl = @(Get-SmbShareAccess -Name $s.Name -ErrorAction SilentlyContinue)
            foreach ($a in $acl) { $aclAll += $a }
            foreach ($a in $acl) {
                if ($a.AccessControlType -eq 'Allow' -and $a.AccountName -match '(?i)everyone|authenticated users|^guest|anonymous' -and $a.AccessRight -match 'Full|Change') {
                    Add-Finding -Id "SHARE-$($s.Name)" -Area 'Shares' -Status 'FAIL' `
                        -Detail "$($s.Name): $($a.AccountName) has $($a.AccessRight) access" `
                        -Hint 'Everyone=Full on a share is a very common scored vuln. Revoke-SmbShareAccess / Grant-SmbShareAccess.'
                }
            }
            if ($s.Name -notmatch '\$$') {
                try {
                    $ntfs = @(Get-Acl ("\\localhost\" + $s.Name) -ErrorAction Stop).Access
                    foreach ($n in $ntfs) {
                        if ($n.AccessControlType -eq 'Allow' -and "$($n.IdentityReference)" -match '(?i)everyone|^guest|anonymous' -and "$($n.FileSystemRights)" -match 'FullControl|Modify|Write') {
                            Add-Finding -Id "NTFS-$($s.Name)" -Area 'Shares' -Status 'WARN' `
                                -Detail "$($s.Name) NTFS: $($n.IdentityReference) = $($n.FileSystemRights)" `
                                -Hint 'NTFS perms are scored separately from share perms. Fix BOTH layers.'
                        }
                    }
                } catch {}
            }
        }
        $aclAll | Export-Csv (Join-Path $ev '40-share-acl.csv') -NoTypeInformation
    }

    # ---- recent files + PII ----------------------------------------------
    Invoke-CP -ReadOnly 'recently modified files' {
        $since = (Get-Date).AddDays(-180)
        $exts = '\.(txt|doc|docx|xls|xlsx|pdf|png|jpg|jpeg|gif|bmp|zip|rar|7z|tar|gz|exe|dll|bat|ps1|vbs|js|db|sqlite|sql|kdbx|log|csv|xml|ini|conf|bak)$'
        $paths = @()
        foreach ($p in (Get-ChildItem C:\Users -Directory -ErrorAction SilentlyContinue)) {
            if ($p.Name -in @('Default','Default User','All Users')) { continue }
            $paths += $p.FullName
        }
        $paths += 'C:\ProgramData','C:\inetpub','C:\Temp','C:\Windows\Temp'
        $rows = @()
        foreach ($pp in $paths) {
            if (-not (Test-Path $pp)) { continue }
            $rows += @(Get-ChildItem $pp -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -gt $since -and $_.Extension -match $exts } |
                Select-Object FullName,Length,LastWriteTime,CreationTime,Extension)
        }
        $rows | Sort-Object LastWriteTime -Descending | Export-Csv (Join-Path $ev '50-recent-files.csv') -NoTypeInformation
        Write-CP "$($rows.Count) recently-modified candidate files catalogued" 'ok'

        $piiHits = @()
        foreach ($f in ($rows | Where-Object { $_.Extension -in '.txt','.csv','.log','.xml','.ini','.conf' } | Select-Object -First 500)) {
            try {
                $c = Get-Content $f.FullName -Raw -ErrorAction Stop
                if (-not $c) { continue }
                if ($c -match '\b\d{3}-\d{2}-\d{4}\b') { $piiHits += [pscustomobject]@{ File=$f.FullName; Type='SSN-pattern' } }
                if ($c -match '(?i)(password|passwd|pwd|secret|api[_-]?key|token)\s*[:=]\s*\S{3,}') { $piiHits += [pscustomobject]@{ File=$f.FullName; Type='cleartext-credential' } }
                if ($c -match '(?i)(card|visa|mastercard|amex|credit)' -and $c -match '\b(?:\d[ -]?){13,19}\b') { $piiHits += [pscustomobject]@{ File=$f.FullName; Type='card-pattern' } }
            } catch {}
        }
        $piiHits | Export-Csv (Join-Path $ev '51-pii-candidates.csv') -NoTypeInformation
        if ($piiHits.Count -gt 0) {
            Add-Finding -Id 'PII' -Area 'Data' -Status 'WARN' -Detail "$($piiHits.Count) file(s) with SSN/card/cleartext-cred patterns" `
                -Hint 'PII exposure is usually a scored item AND a README task. Record the exact path in the report. Do NOT delete the file.'
        } else {
            Add-Finding -Id 'PII' -Area 'Data' -Status 'PASS' -Detail 'no SSN/card/cleartext-credential patterns in document files'
        }
    }

    # ---- forensic artifacts ----------------------------------------------
    Invoke-CP -ReadOnly 'forensic artifacts (prefetch/recent/USB/MOTW)' {
        $pfDir = Join-Path $ev 'prefetch'
        New-Item -ItemType Directory -Path $pfDir -Force -ErrorAction SilentlyContinue | Out-Null
        Copy-Item 'C:\Windows\Prefetch\*.pf' $pfDir -Force -ErrorAction SilentlyContinue
        $pf = @(Get-ChildItem C:\Windows\Prefetch -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
        $pf | Select-Object Name,LastWriteTime,CreationTime | Export-Csv (Join-Path $ev '60-prefetch.csv') -NoTypeInformation
        $pf | Select-Object -First 30 | ForEach-Object {
            Write-Host ("   prefetch {0}  {1}" -f $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm'), $_.Name)
        }

        foreach ($u in (Get-ChildItem C:\Users -Directory -ErrorAction SilentlyContinue)) {
            $rp = Join-Path $u.FullName 'AppData\Roaming\Microsoft\Windows\Recent'
            if (Test-Path $rp) {
                Get-ChildItem $rp -Recurse -File -ErrorAction SilentlyContinue |
                    Select-Object @{n='User';e={$u.Name}},Name,LastWriteTime |
                    Export-Csv -Append (Join-Path $ev '61-recent.csv') -NoTypeInformation -ErrorAction SilentlyContinue
            }
            $jl = Join-Path $u.FullName 'AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations'
            if (Test-Path $jl) {
                Get-ChildItem $jl -File -ErrorAction SilentlyContinue |
                    Select-Object @{n='User';e={$u.Name}},Name,Length,LastWriteTime |
                    Export-Csv -Append (Join-Path $ev '66-jumplists.csv') -NoTypeInformation -ErrorAction SilentlyContinue
            }
        }

        $md = Get-Item 'HKLM:\SYSTEM\MountedDevices' -ErrorAction SilentlyContinue
        if ($md) {
            $md.GetValueNames() | Where-Object { $_ -like '\DosDevices\*' } | Set-Content (Join-Path $ev '62-mounted-devices.txt')
        }
        Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*' -ErrorAction SilentlyContinue |
            Select-Object FriendlyName,DeviceDesc,Mfg,PSChildName |
            Export-Csv (Join-Path $ev '62-usbstor.csv') -NoTypeInformation
        if (Test-Path 'C:\Windows\INF\setupapi.dev.log') {
            Copy-Item 'C:\Windows\INF\setupapi.dev.log' (Join-Path $ev '62-setupapi.dev.log') -Force -ErrorAction SilentlyContinue
        }

        @(
            'C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\History',
            'C:\Users\*\AppData\Local\Mozilla\Firefox\Profiles\*\places.sqlite',
            'C:\Users\*\AppData\Local\Microsoft\Edge\User Data\Default\History',
            'C:\Users\*\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat'
        ) | ForEach-Object { Get-Item $_ -ErrorAction SilentlyContinue | Select-Object FullName,Length,LastWriteTime } |
            Export-Csv (Join-Path $ev '63-browser-artifacts.csv') -NoTypeInformation

        Get-ChildItem 'C:\$Recycle.Bin' -Recurse -Force -ErrorAction SilentlyContinue |
            Select-Object FullName,Length,LastWriteTime |
            Export-Csv (Join-Path $ev '64-recyclebin.csv') -NoTypeInformation

        # mark of the web: "this file came from the internet, here is the URL"
        $zoi = @()
        $scanRoots = @('C:\Users','C:\Temp','C:\Downloads','C:\ProgramData')
        foreach ($sr in $scanRoots) {
            if (-not (Test-Path $sr)) { continue }
            foreach ($f in @(Get-ChildItem $sr -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1500)) {
                try {
                    $s = Get-Item $f.FullName -Stream Zone.Identifier -ErrorAction Stop
                    if ($s) { $zoi += [pscustomobject]@{ File=$f.FullName; Size=$s.Length; LastWrite=$f.LastWriteTime } }
                } catch {}
            }
        }
        $zoi | Export-Csv (Join-Path $ev '65-zone-identifiers.csv') -NoTypeInformation
        if ($zoi.Count -gt 0) {
            Add-Finding -Id 'FORENSIC-ZOI' -Area 'Forensics' -Status 'INFO' -Detail "$($zoi.Count) file(s) carry a Mark-of-the-Web" `
                -Hint 'Get-Content <file> -Stream Zone.Identifier -- shows the download URL. Classic forensic answer.'
        }
    }

    # ---- programs / hosts / update / defender state ------------------------
    Invoke-CP -ReadOnly 'installed programs' {
        $paths = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                   'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
                   'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*')
        $p = @(Get-ItemProperty $paths -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName })
        $p | Select-Object DisplayName,DisplayVersion,Publisher,InstallDate,InstallLocation,UninstallString |
            Sort-Object DisplayName | Export-Csv (Join-Path $ev '70-programs.csv') -NoTypeInformation
        $suspect = '(?i)teamviewer|ammyy|anydesk|logmein|vnc|tightvnc|realvnc|ngrok|nmap|wireshark|mimikatz|netcat|ncat|putty|filezilla|torrent|utorrent|bittorrent|xmrig|minergate|keylog|procexp|procmon|process hacker|nirsoft|pwdump|quarks|psexec|hydra|john the ripper|hashcat|ophcrack|cain|angry ip|advanced ip|metasploit|burp|nessus|emule|skype|discord|steam'
        foreach ($x in $p) {
            if ($x.DisplayName -match $suspect) {
                Add-Finding -Id "PROG-$($x.DisplayName)" -Area 'Software' -Status 'WARN' `
                    -Detail "installed: $($x.DisplayName) $($x.DisplayVersion)" `
                    -Hint 'Remote-access tooling, p2p, media, or attack tools. Check the README approved list, uninstall through Settings > Apps, record it.'
            }
        }
    }

    Invoke-CP -ReadOnly 'hosts file' {
        Copy-Item C:\Windows\System32\drivers\etc\hosts (Join-Path $ev 'hosts.txt') -Force -ErrorAction SilentlyContinue
        $h = @(Get-Content C:\Windows\System32\drivers\etc\hosts -ErrorAction SilentlyContinue | Where-Object { $_ -and $_ -notmatch '^\s*#' })
        foreach ($line in $h) {
            if ($line -notmatch '^\s*(127\.0\.0\.1|::1)\s+localhost(\s+.*)?$' -and $line -notmatch '^\s*127\.0\.1\.1\s') {
                Add-Finding -Id 'HOSTS' -Area 'Network' -Status 'WARN' -Detail "hosts entry: $($line.Trim())" `
                    -Hint 'Redirect entries in hosts are used for phishing and to break updates. Verify each against the README.'
            }
        }
    }

    Invoke-CP -ReadOnly 'windows update + defender state' {
        $st = Get-CPStartType 'wuauserv'
        Add-Finding -Id 'WU' -Area 'Updates' -Status $(if ($st -eq 'Disabled') {'FAIL'} elseif ($st -eq 'Unknown') {'WARN'} else {'PASS'}) `
            -Detail "wuauserv start type = $st" `
            -Hint 'Disabled Windows Update is a scored vuln on nearly every image. Fix it in the defender section.'
        try {
            $mp = Get-MpComputerStatus -ErrorAction Stop
            Add-Finding -Id 'DEF-RT' -Area 'Defender' -Status $(if ($mp.RealTimeProtectionEnabled) {'PASS'} else {'FAIL'}) `
                -Detail "RealTimeProtection = $($mp.RealTimeProtectionEnabled)"
            Add-Finding -Id 'DEF-SIGAGE' -Area 'Defender' -Status $(if ($mp.AntivirusSignatureAge -le 7) {'PASS'} else {'WARN'}) `
                -Detail "signature age = $($mp.AntivirusSignatureAge) day(s)" `
                -Hint 'Out-of-date definitions still get noted in the report even when the image is offline.'
        } catch {
            Add-Finding -Id 'DEF-STATUS' -Area 'Defender' -Status 'WARN' -Detail 'Get-MpComputerStatus unavailable' `
                -Hint 'Server Core or third-party AV. Check Security Center manually.'
        }
    }

    Invoke-CP -ReadOnly 'event log checks' {
        Get-WinEvent -ListLog Security,System,Application -ErrorAction SilentlyContinue |
            Select-Object LogName,IsEnabled,MaximumSizeInBytes,RecordCount |
            Export-Csv (Join-Path $ev '80-eventlogs.csv') -NoTypeInformation
        foreach ($lg in @('Security','System','Application')) {
            try {
                $c = @(Get-WinEvent -LogName $lg -MaxEvents 1 -ErrorAction Stop).Count
                if ($c -eq 0) {
                    Add-Finding -Id "LOG-EMPTY-$lg" -Area 'Logging' -Status 'WARN' -Detail "$lg log has no events" `
                        -Hint 'An empty log can mean it was cleared -- which is itself attacker evidence. Check event ID 1102.'
                }
            } catch {}
        }
        try {
            $cleared = @(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} -MaxEvents 20 -ErrorAction Stop)
            if ($cleared.Count -gt 0) {
                Add-Finding -Id 'LOG-CLEARED' -Area 'Forensics' -Status 'FAIL' `
                    -Detail "Security log was cleared $($cleared.Count) time(s), most recent $($cleared[0].TimeCreated)" `
                    -Hint 'Event 1102 = "audit log was cleared". That is a scored finding AND a forensic answer. Record who and when.'
            }
        } catch {}
    }

    Write-CP ("evidence collected -> {0} files" -f @(Get-ChildItem $ev -Recurse -File -ErrorAction SilentlyContinue).Count) 'ok'
}
# ------------------------------------------------------------------------------
# users + local security policy.
# reconciles local accounts against users.txt / admins.txt (copied from the
# README), then merges the scored password/lockout/audit policy via secedit.
# it never deletes anything without asking, and never touches a domain DC's
# policy with secedit (that lives in the Default Domain Policy GPO).
# ------------------------------------------------------------------------------
function Invoke-Users {
    Write-Banner 'USERS + LOCAL SECURITY POLICY'
    if (-not (Enter-CPPhase 'users' -Mutating)) { return }
    $isDC = $false
    if (-not $script:IdentitySid) { throw 'cannot protect the executing account without its SID' }

    # ---- 1. reconcile accounts against the README lists -------------------
    $usersPath  = Join-Path $PSScriptRoot 'users.txt'
    $adminsPath = Join-Path $PSScriptRoot 'admins.txt'
    $admins = @(Read-List $adminsPath '# administrators from the README, one per line')
    $users  = @(Read-List $usersPath  '# standard (non-admin) users from the README, one per line')
    $all = @($users + $admins | Select-Object -Unique)
    $me = $env:USERNAME

    # built-in guest / pseudo accounts are always safe to disable, even when
    # users.txt and admins.txt have not been filled in yet.
    if (-not $isDC -and $all.Count -eq 0) {
        foreach ($rid in 501,503,504) {
            Get-CPUsers | Where-Object { $_.SID -match ("-$rid`$") -and $_.Enabled -and $_.SID -ne $script:IdentitySid } | ForEach-Object {
                $n = $_.Name
                Invoke-CP "disable built-in account '$n'" { Disable-LocalUser -Name $n -ErrorAction Stop } | Out-Null
            }
        }
    }

    if ($all.Count -gt 0) {
        foreach ($u in @(Get-CPUsers)) {
            $rid = 500; try { $rid = [int](($u.SID -split '-')[-1]) } catch {}
            if ($rid -in 500,501,503,504) { continue }        # built-ins, handled below
            if ($all -contains $u.Name) { continue }
            Write-CP ("'$($u.Name)' is not in users.txt / admins.txt (enabled: $($u.Enabled))" ) 'warn'
            if ($u.SID -eq $script:IdentitySid) {
                Add-Review "you are logged in as '$me' but it is not on the lists -- re-read the README"
                continue
            }
            if ($Paranoid -or $script:Dry -or $Force) { Add-Review "unlisted account '$($u.Name)' (read-only/non-interactive: no action)"; continue }
            Write-Host ''
            $c = Read-Host '  (R)emove, (D)isable, or (S)kip [S]'
            $n = $u.Name
            if ($c -match '^[Rr]') {
                $removed = Invoke-CP "remove user '$n'" {
                    Remove-LocalUser -Name $n -ErrorAction Stop
                    if (@(Get-CPUsers | Where-Object { $_.SID -eq $u.SID }).Count) { throw 'account still exists' }
                }
                if ($removed) { Register-Change -What "user $n" -Old 'present' -New 'removed (not undoable)' }
            } elseif ($c -match '^[Dd]') {
                $disabled = Invoke-CP "disable user '$n'" {
                    Disable-LocalUser -Name $n -ErrorAction Stop
                    if (@(Get-CPUsers | Where-Object { $_.SID -eq $u.SID -and $_.Enabled }).Count) { throw 'account still enabled' }
                }
                if ($disabled) { Register-Change -What "user $n" -Old 'enabled' -New 'disabled' }
            }
        }

        # built-in accounts: guest (501) and the pseudo accounts get disabled,
        # never deleted. RID 500 (built-in admin) is left alone -- renaming or
        # disabling it breaks scored checks and can lock you out.
        foreach ($rid in 501,503,504) {
            Get-CPUsers | Where-Object { $_.SID -match ("-$rid`$") -and $_.Enabled -and $_.SID -ne $script:IdentitySid } | ForEach-Object {
                $n = $_.Name
                Invoke-CP "disable built-in account '$n'" { Disable-LocalUser -Name $n -ErrorAction Stop } | Out-Null
            }
        }

        # administrators group: local users only. domain members are reported,
        # not touched -- demoting a domain admin is not your call.
        $current = @(Get-AdminMemberNames)
        foreach ($n in $current) {
            if ($admins -contains $n) { continue }
            $member = @(Get-CPUsers | Where-Object { $_.Name -ieq $n }) | Select-Object -First 1
            if (-not $member -or $member.SID -eq $script:IdentitySid) {
                Add-Review "'$me' is an admin but is not in admins.txt -- check the README"
                continue
            }
            if ($Paranoid -or $script:Dry -or $Force) { Add-Review "admin '$n' is not in admins.txt (no action)"; continue }
            Write-Host ''
            $c = Read-Host "  '$n' is an Administrator but not in admins.txt. Demote? (y/N)"
            if ($c -match '^[Yy]') {
                $demoted = Invoke-CP "remove '$n' from Administrators" {
                    Remove-LocalGroupMember -SID 'S-1-5-32-544' -Member $member.SID -ErrorAction Stop
                    if (@(Get-AdminMemberNames) -contains $n) { throw 'administrator membership unchanged' }
                }
                if ($demoted) { Register-Change -What "admin group: $n" -Old 'member' -New 'removed' }
            } else {
                Add-Review "admin '$n' left in Administrators -- verify against the README"
            }
        }
        foreach ($n in $admins) {
            if ($current -notcontains $n -and (Get-CPUsers | Where-Object { $_.Name -eq $n })) {
                if ($Paranoid -or $script:Dry -or $Force) { Add-Review "'$n' should be an admin per admins.txt (no action)"; continue }
                Write-Host ''
                $c = Read-Host "  '$n' should be an admin per admins.txt. Add to Administrators? (y/N)"
                if ($c -match '^[Yy]') {
                    Invoke-CP "add '$n' to Administrators" {
                        $member = @(Get-CPUsers | Where-Object { $_.Name -ieq $n }) | Select-Object -First 1
                        if (-not $member) { throw 'local user no longer exists' }
                        Add-LocalGroupMember -SID 'S-1-5-32-544' -Member $member.SID -ErrorAction Stop
                        if (@(Get-AdminMemberNames) -notcontains $n) { throw 'administrator membership unchanged' }
                    } | Out-Null
                }
            }
        }

        # one strong password on every authorized account (optional)
        if (-not ($Paranoid -or $script:Dry -or $Force)) {
            Write-Host ''
            $c = Read-Host '  set ONE new strong password on every authorized account? (y/N)'
            if ($c -match '^[Yy]') {
                $minimumLength = 14
                $policy = Get-SeceditInf
                foreach ($line in @(Get-Content -LiteralPath $policy -ErrorAction Stop)) {
                    if ($line -match '^\s*MinimumPasswordLength\s*=\s*(\d+)') { $minimumLength = [Math]::Max(14,[int]$Matches[1]) }
                }
                $p1 = Read-Host "  new password ($minimumLength+ chars; password resets are not undoable)" -AsSecureString
                $p2 = Read-Host '  again' -AsSecureString
                $ptr1 = [IntPtr]::Zero; $ptr2 = [IntPtr]::Zero
                try {
                    $ptr1 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($p1)
                    $ptr2 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($p2)
                    $a = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr1)
                    $b = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr2)
                    $validPassword = ($a -ceq $b -and $a.Length -ge $minimumLength)
                } finally {
                    if ($ptr1 -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr1) }
                    if ($ptr2 -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr2) }
                    $a = $null; $b = $null
                }
                if (-not $validPassword) {
                    Write-CP 'passwords differ (case-sensitive) or do not meet the intended minimum length; skipped' 'warn'
                } else {
                    foreach ($n in $all) {
                        $exists = Get-CPUsers | Where-Object { $_.Name -eq $n }
                        if ($exists) {
                            Invoke-CP "set password on '$n'" {
                                Set-LocalUser -Name $n -Password $p1 -PasswordNeverExpires $false -UserMayChangePassword $true -ErrorAction Stop
                            } | Out-Null
                        } else {
                            Write-Host ''
                            $cc = Read-Host "  '$n' is on the lists but does not exist. Create it? (y/N)"
                            if ($cc -match '^[Yy]') {
                                Invoke-CP "create '$n'" {
                                    New-LocalUser -Name $n -Password $p1 -ErrorAction Stop | Out-Null
                                    $created = Get-LocalUser -Name $n -ErrorAction Stop
                                    Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $created.SID -ErrorAction Stop
                                    if ($admins -contains $n) { Add-LocalGroupMember -SID 'S-1-5-32-544' -Member $created.SID -ErrorAction Stop }
                                } | Out-Null
                            }
                        }
                    }
                    Write-CP 'password reset attempts finished; check each result and record the new password securely' 'warn'
                }
                $p1.Dispose(); $p2.Dispose()
            }
        }

        # password flags on every enabled account
        foreach ($u in @(Get-CPUsers | Where-Object { $_.Enabled -and $all -contains $_.Name })) {
            $n = $u.Name
            if ($null -eq $u.PasswordExpires) {
                Invoke-CP "let password expire for '$n'" {
                    Set-LocalUser -Name $n -PasswordNeverExpires $false -ErrorAction Stop
                } | Out-Null
            }
            if (-not $u.PasswordRequired) {
                Invoke-CP "require a password for '$n'" {
                    Invoke-CPNative net.exe @('user',$n,'/passwordreq:yes') | Out-Null
                    if (-not (@(Get-CPUsers | Where-Object { $_.SID -eq $u.SID }) | Select-Object -First 1).PasswordRequired) { throw 'password-required flag unchanged' }
                } | Out-Null
            }
        }
    } else {
        Write-CP 'users.txt / admins.txt are empty -- only built-in account fixes and policy will run.' 'warn'
        Add-Review 'users.txt/admins.txt empty: fill them from the README and re-run the users section'
    }

    # built-in Administrator (RID 500) is left enabled by default because
    # disabling the account you are logged in as locks you out. opt in with
    # -DisableBuiltinAdmin once the README confirms it is not required.
    if ($DisableBuiltinAdmin) {
        $builtinAdmin = @(Get-CPUsers | Where-Object { $_.SID -match '-500$' }) | Select-Object -First 1
        if ($builtinAdmin -and $builtinAdmin.Enabled) {
            if ($builtinAdmin.SID -eq $script:IdentitySid) {
                Add-Review "built-in Administrator '$($builtinAdmin.Name)' is the account you are using -- NOT disabled"
            } else {
                $disabled = Invoke-CP "disable built-in Administrator '$($builtinAdmin.Name)'" {
                    try { Disable-LocalUser -Name $builtinAdmin.Name -ErrorAction Stop }
                    catch {
                        Invoke-CPNative net.exe @('user',$builtinAdmin.Name,'/active:no') | Out-Null
                    }
                    if (@(Get-CPUsers | Where-Object { $_.SID -eq $builtinAdmin.SID -and $_.Enabled }).Count) { throw 'built-in Administrator still enabled' }
                }
                if ($disabled) {
                    Register-Change -What "user $($builtinAdmin.Name)" -Old 'enabled' -New 'disabled'
                    Add-Finding -Id 'ACC-BUILTIN-ADMIN' -Area 'Accounts' -Status 'PASS' -Detail 'built-in Administrator disabled'
                }
            }
        } elseif ($builtinAdmin) {
            Add-Finding -Id 'ACC-BUILTIN-ADMIN' -Area 'Accounts' -Status 'PASS' -Detail 'built-in Administrator already disabled'
        }
    } else {
        Add-Finding -Id 'ACC-BUILTIN-ADMIN' -Area 'Accounts' -Status 'INFO' -Detail 'built-in Administrator left enabled' `
            -Hint 'Pass -DisableBuiltinAdmin only after the README says the built-in account is not required. Disabling it can lock you out.'
    }

    if ($isDC) {
        Add-Finding -Id 'ACC-ADMIN500' -Area 'Accounts' -Status 'SKIP' -Detail 'domain controller: RID-500 is a domain account'
    } else {
        $rid500 = @(Get-CPUsers | Where-Object { $_.SID -match '-500$' }) | Select-Object -First 1
        if ($rid500) {
            if ($rid500.PasswordRequired) {
                Add-Finding -Id 'ACC-ADMIN500' -Area 'Accounts' -Status 'PASS' -Detail 'built-in Administrator requires a password'
            } else {
                Add-Finding -Id 'ACC-ADMIN500' -Area 'Accounts' -Status 'FAIL' -Detail 'built-in Administrator does not require a password' `
                    -Hint 'Set a strong password on the RID-500 account (net user Administrator <password>) before disabling it or leaving it active.'
            }
        } else {
            Add-Finding -Id 'ACC-ADMIN500' -Area 'Accounts' -Status 'WARN' -Detail 'could not find the RID-500 account'
        }
    }

    $acctNames = (@(Get-CPUsers) | ForEach-Object { $_.Name }) -join ', '
    Add-Finding -Id 'ACC-INVENTORY' -Area 'Accounts' -Status 'INFO' `
        -Detail ("local accounts: {0}" -f $acctNames) `
        -Hint 'Compare this list, one name at a time, against the README authorized-user list. Not authorized = remove it. Authorized = leave it alone. Removing an authorized user is one of the biggest penalties in the competition.'

    # ---- 2. secedit policy MERGE ------------------------------------------
    if (-not $isDC) {
        Write-CP 'merging local security policy (secedit)' 'step'
        Invoke-CP 'secedit policy merge (password/lockout/audit/registry values)' {
            $inf = Get-SeceditInf
            $lines = New-Object 'System.Collections.Generic.List[string]'
            Get-Content $inf | ForEach-Object { $null = $lines.Add($_) }

            # [System Access] -- the classic scored items
            $sa = [ordered]@{
                'MinimumPasswordAge'           = '1'
                'MaximumPasswordAge'           = '90'
                'MinimumPasswordLength'        = '14'
                'PasswordComplexity'           = '1'
                'PasswordHistorySize'          = '24'
                'LockoutBadCount'              = '5'
                'ResetLockoutCount'            = '15'
                'LockoutDuration'              = '15'
                'RequireLogonToChangePassword' = '0'
                'ForceLogoffWhenHourExpire'    = '1'
                'ClearTextPassword'            = '0'
                'LSAAnonymousNameLookup'       = '0'
                'EnableGuestAccount'           = '0'
            }
            foreach ($k in $sa.Keys) { $null = Set-SeceditValue -Lines $lines -Section 'System Access' -Key $k -Value $sa[$k] -PreserveStronger }
            $numeric = @{}
            foreach ($line in $lines) {
                if ($line -match '^\s*(\w+)\s*=\s*(-?\d+)\s*$') { $numeric[$Matches[1]] = [int]$Matches[2] }
            }
            if ($numeric.MaximumPasswordAge -gt 0 -and $numeric.MinimumPasswordAge -ge $numeric.MaximumPasswordAge) {
                throw 'existing minimum/maximum password ages conflict with this baseline; review manually'
            }
            if ($numeric.LockoutDuration -ne 0 -and $numeric.LockoutDuration -lt $numeric.ResetLockoutCount) {
                $numeric.LockoutDuration = $numeric.ResetLockoutCount
                $null = Set-SeceditValue $lines 'System Access' 'LockoutDuration' ([string]$numeric.LockoutDuration)
            }

            # [Event Audit] -- 3 = success + failure
            $ea = [ordered]@{
                'AuditSystemEvents'    = '3'; 'AuditLogonEvents'     = '3'
                'AuditObjectAccess'    = '3'; 'AuditPrivilegeUse'    = '3'
                'AuditPolicyChange'    = '3'; 'AuditAccountManage'   = '3'
                'AuditProcessTracking' = '3'; 'AuditDSAccess'       = '3'
                'AuditAccountLogon'    = '3'
            }
            foreach ($k in $ea.Keys) { $null = Set-SeceditValue -Lines $lines -Section 'Event Audit' -Key $k -Value $ea[$k] }

            # [Registry Values] -- type 4 = DWORD, 1 = string
            $rv = [ordered]@{
                'MACHINE\System\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse'                 = '4,1'
                'MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash'                              = '4,1'
                'MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymous'                     = '4,1'
                'MACHINE\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM'                   = '4,1'
                'MACHINE\System\CurrentControlSet\Control\Lsa\LMCompatibilityLevel'                   = '4,5'
                'MACHINE\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous'            = '4,0'
                'MACHINE\System\CurrentControlSet\Control\Lsa\ForceGuest'                           = '4,0'
                'MACHINE\System\CurrentControlSet\Services\LDAP\LDAPClientIntegrity'                 = '4,1'
                'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal'    = '4,1'
                'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel'     = '4,1'
                'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SignSecureChannel'    = '4,1'
                'MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters\RequireSecuritySignature' = '4,1'
                'MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters\EnableSecuritySignature'  = '4,1'
                'MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature' = '4,1'
                'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateCDRoms'      = '1,1'
                'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AllocateFloppies'     = '1,1'
                'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\CachedLogonsCount'    = '1,2'
                'MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ScRemoveOption'       = '1,1'
                'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin' = '4,2'
                'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser'  = '4,0'
                'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableCAD'      = '4,0'
                'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName'    = '4,1'
                'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA'      = '4,1'
                'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop'      = '4,1'
                'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ShutdownWithoutLogon'       = '4,0'
                'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun'        = '4,255'
                'USER\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments\SaveZoneInformation'  = '4,2'
            }
            foreach ($k in $rv.Keys) { $null = Set-SeceditValue -Lines $lines -Section 'Registry Values' -Key $k -Value $rv[$k] }

            # [Privilege Rights] -- only the safe deny entries. clobbering the
            # rest locks you out; the full assignment is a secpol.msc by-hand
            # job against the README. S-1-5-32-546 = Guests.
            $pr = [ordered]@{
                'SeDenyNetworkLogonRight'           = '*S-1-5-32-546'
                'SeDenyInteractiveLogonRight'       = '*S-1-5-32-546'
                'SeDenyRemoteInteractiveLogonRight'  = '*S-1-5-32-546'
                'SeDenyBatchLogonRight'             = '*S-1-5-32-546'
                'SeDenyServiceLogonRight'           = '*S-1-5-32-546'
            }
            foreach ($k in $pr.Keys) { $null = Set-SeceditValue -Lines $lines -Section 'Privilege Rights' -Key $k -Value $pr[$k] -Union }

            $out = Join-Path $script:EvDir 'secpol-hardened.inf'
            Set-Content -LiteralPath $out -Value $lines -Encoding Unicode -ErrorAction Stop
            if (-not (Apply-SeceditInf -InfPath $out)) {
                # Only reuse the already merged numeric targets; never reset a
                # stronger live policy to fixed net.exe fallback constants.
                if (Confirm-CP 'Secedit apply failed. Apply ONLY the merged numeric account policy through net accounts? User rights/registry still need review.') {
                    Invoke-CPNative net.exe @('accounts',("/minpwlen:" + $numeric.MinimumPasswordLength),
                        ("/maxpwage:" + $numeric.MaximumPasswordAge),("/minpwage:" + $numeric.MinimumPasswordAge),
                        ("/uniquepw:" + $numeric.PasswordHistorySize),("/lockoutduration:" + $numeric.LockoutDuration),
                        ("/lockoutthreshold:" + $numeric.LockoutBadCount),("/lockoutwindow:" + $numeric.ResetLockoutCount)) | Out-Null
                }
                throw 'secedit policy was not fully applied; any numeric fallback must also be verified'
            }
            $verifyInf = Get-SeceditInf
            $actual = Get-Content -LiteralPath $verifyInf -Raw -ErrorAction Stop
            foreach ($key in $sa.Keys) {
                $expected = @($lines | Where-Object { $_ -match ('^' + [regex]::Escape($key) + '\s*=') })[0]
                if ($actual -notmatch ('(?m)^\s*' + [regex]::Escape($expected) + '\s*$')) { throw "policy postcondition failed: $key" }
            }
            foreach ($key in $pr.Keys) {
                if ($actual -notmatch ('(?m)^\s*' + [regex]::Escape($key) + '\s*=([^\r\n]*)') -or
                    @($Matches[1] -split ',' | ForEach-Object { $_.Trim() }) -notcontains '*S-1-5-32-546') { throw "Guest denial not verified: $key" }
            }
            Add-Finding -Id 'POL-APPLY' -Area 'Policy' -Status 'PASS' -Detail 'merged account policy and Guest deny rights applied and re-exported'
            Remove-Item $inf -Force -ErrorAction SilentlyContinue
        }
        Invoke-CP 'gpupdate /force (30 second wait)' { Invoke-CPNative gpupdate.exe @('/force','/wait:30') | Out-Null } | Out-Null

        # screen saver lock -- very commonly scored, easy to miss
        Invoke-CP 'screen saver lock (10 min, password protected)' {
            Set-CPReg 'HKCU:\Control Panel\Desktop' 'ScreenSaveActive'    '1'   String | Out-Null
            Set-CPReg 'HKCU:\Control Panel\Desktop' 'ScreenSaverIsSecure' '1'   String | Out-Null
            Set-CPReg 'HKCU:\Control Panel\Desktop' 'ScreenSaveTimeOut'   '600' String | Out-Null
            $ssd = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop'
            Set-CPReg $ssd 'ScreenSaveActive'    '1'   String -Id 'POL-SCREENSAVE' -Area 'Policy' | Out-Null
            Set-CPReg $ssd 'ScreenSaverIsSecure' '1'   String | Out-Null
            Set-CPReg $ssd 'ScreenSaveTimeOut'   '600' String | Out-Null
        }

        # autologon must be off and any cached DefaultPassword must go
        $autoOk = Invoke-CP 'autologon check' {
            $wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
            $al = Get-CPReg -Path $wl -Name 'AutoAdminLogon'
            $pw = Get-CPReg -Path $wl -Name 'DefaultPassword'
            if ("$al" -eq '1' -or $pw) {
                if (-not (Set-CPReg $wl 'AutoAdminLogon' '0' String)) { throw 'could not disable autologon' }
                foreach ($n in 'DefaultPassword','DefaultUserName','DefaultDomainName','AltDefaultUserName','AltDefaultDomainName') {
                    if (-not (Remove-CPRegValue $wl $n)) { throw "could not remove $n" }
                }
                Register-Change -What 'Winlogon autologon' -Old "AutoAdminLogon=$al" -New 'removed'
            }
        }
        if ($autoOk) { Add-Finding -Id 'ACC-AUTOLOGON' -Area 'Accounts' -Status 'PASS' -Detail 'autologon disabled or absent; cached credentials removed when present' }
        Add-Finding -Id 'POL-URIGHTS' -Area 'Policy' -Status 'INFO' -Detail 'User Rights Assignment not fully rewritten' `
            -Hint 'Open secpol.msc > Local Policies > User Rights Assignment and compare against the README (who can log on remotely, debug programs, act as part of the OS...). The script only set the Guest denials.'
    }
}
# ------------------------------------------------------------------------------
# registry hardening -- the stuff secedit does not reach
# ------------------------------------------------------------------------------
function Invoke-Registry {
    Write-Banner 'REGISTRY HARDENING'
    if (-not (Enter-CPPhase 'registry' -Mutating)) { return }

    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    Set-CPReg -Path $lsa -Name 'RestrictAnonymous'          -Value 1 -Id 'REG-RestrictAnonymous' -Area 'Registry' | Out-Null
    Set-CPReg -Path $lsa -Name 'RestrictAnonymousSAM'       -Value 1 -Id 'REG-RestrictAnonSAM'   -Area 'Registry' | Out-Null
    Set-CPReg -Path $lsa -Name 'NoLMHash'                   -Value 1 -Id 'REG-NoLMHash'          -Area 'Registry' | Out-Null
    Set-CPReg -Path $lsa -Name 'LMCompatibilityLevel'       -Value 5 -Id 'REG-LMCompat'          -Area 'Registry' | Out-Null
    Set-CPReg -Path $lsa -Name 'LimitBlankPasswordUse'      -Value 1 -Id 'REG-BlankPwUse'        -Area 'Registry' | Out-Null
    Set-CPReg -Path $lsa -Name 'EveryoneIncludesAnonymous'  -Value 0 -Id 'REG-EveryoneAnon'      -Area 'Registry' | Out-Null
    Set-CPReg -Path $lsa -Name 'ForceGuest'                -Value 0 -Id 'REG-ForceGuest'        -Area 'Registry' | Out-Null
    Set-CPReg -Path $lsa -Name 'DisableDomainCreds'         -Value 1 -Id 'REG-DisableDomainCreds' -Area 'Registry' | Out-Null
    # WDigest keeps cleartext passwords in LSASS -- the mimikatz special
    Set-CPReg -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -Value 0 -Id 'REG-WDigest' -Area 'Registry' | Out-Null
    # RunAsPPL=1 can create a UEFI lock. Only supported builds get the
    # reversible value 2; existing protection is never downgraded.
    $ppl = Get-CPReg -Path $lsa -Name 'RunAsPPL'
    $build = 0
    try { $build = [int](Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).BuildNumber } catch {}
    if ($ppl -notin 1,2 -and $build -ge 22621) {
        Set-CPReg -Path $lsa -Name 'RunAsPPL' -Value 2 -Id 'REG-RunAsPPL' -Area 'Registry' | Out-Null
    } elseif ($ppl -notin 1,2) {
        Add-Review 'LSA protection requires platform/driver review on this build; no new UEFI lock was requested. Configure manually after checking compatibility.'
    } else {
        Add-Finding -Id 'REG-RunAsPPL' -Area 'Registry' -Status 'PASS' -Detail "RunAsPPL = $ppl"
    }
    Set-CPReg -Path "$lsa\MSV1_0" -Name 'NTLMMinClientSec'          -Value 537395200 -Id 'REG-NTLMMinClient' -Area 'Registry' | Out-Null
    Set-CPReg -Path "$lsa\MSV1_0" -Name 'NTLMMinServerSec'          -Value 537395200 -Id 'REG-NTLMMinServer' -Area 'Registry' | Out-Null
    Set-CPReg -Path "$lsa\MSV1_0" -Name 'allownullsessionfallback'   -Value 0 | Out-Null
    Set-CPReg -Path "$lsa\pku2u"  -Name 'AllowOnlineID'             -Value 0 | Out-Null

    # netlogon: refuse weak machine-account crypto and rotate the password
    $nl = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
    Set-CPReg -Path $nl -Name 'RequireStrongKey'     -Value 1  -Id 'REG-StrongKey'   -Area 'Registry' | Out-Null
    Set-CPReg -Path $nl -Name 'MaximumPasswordAge'   -Value 30 -Id 'REG-MachinePwAge' -Area 'Registry' | Out-Null

    $sm = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    Set-CPReg -Path "$sm\Kernel"            -Name 'ObCaseInsensitive'      -Value 1 | Out-Null
    Set-CPReg -Path "$sm\Memory Management" -Name 'ClearPageFileAtShutdown' -Value 1 -Id 'REG-ClearPagefile' -Area 'Registry' | Out-Null
    Set-CPReg -Path $sm                      -Name 'ProtectionMode'          -Value 1 | Out-Null

    # ---- UAC --------------------------------------------------------------
    $pol = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    Set-CPReg -Path $pol -Name 'EnableLUA'                  -Value 1 -Id 'REG-UAC-EnableLUA'     -Area 'UAC' | Out-Null
    Set-CPReg -Path $pol -Name 'ConsentPromptBehaviorAdmin' -Value 2 -Id 'REG-UAC-ConsentAdmin'  -Area 'UAC' | Out-Null
    Set-CPReg -Path $pol -Name 'ConsentPromptBehaviorUser'  -Value 0 -Id 'REG-UAC-ConsentUser'   -Area 'UAC' | Out-Null
    Set-CPReg -Path $pol -Name 'PromptOnSecureDesktop'      -Value 1 -Id 'REG-UAC-SecureDesktop' -Area 'UAC' | Out-Null
    Set-CPReg -Path $pol -Name 'FilterAdministratorToken'   -Value 1 -Id 'REG-UAC-FilterAdmin'   -Area 'UAC' | Out-Null
    Set-CPReg -Path $pol -Name 'EnableInstallerDetection'  -Value 1 | Out-Null
    Set-CPReg -Path $pol -Name 'EnableVirtualization'      -Value 1 | Out-Null
    Set-CPReg -Path $pol -Name 'EnableSecureUIAPaths'      -Value 1 | Out-Null
    Set-CPReg -Path $pol -Name 'DisableCAD'                -Value 0 -Id 'REG-CAD' -Area 'UAC' | Out-Null
    Set-CPReg -Path $pol -Name 'DontDisplayLastUserName'   -Value 1 -Id 'REG-LastUser' -Area 'UAC' | Out-Null
    Set-CPReg -Path $pol -Name 'ShutdownWithoutLogon'      -Value 0 -Id 'REG-ShutdownNoLogon' -Area 'UAC' | Out-Null
    Set-CPReg -Path $pol -Name 'InactivityTimeoutSecs'     -Value 900 | Out-Null
    if ($Aggressive -and (Confirm-CP 'AGGRESSIVE: block Microsoft-account sign-ins/linking? Skip if any authorized user signs in with a Microsoft account.' -InteractiveOnly)) {
        Set-CPReg -Path $pol -Name 'NoConnectedUser' -Value 3 -Id 'REG-NoMSAccount' -Area 'UAC' | Out-Null
    } else { Add-Review 'Microsoft-account sign-in policy preserved; blocking it can lock out authorized users' }
    Set-CPReg -Path $pol -Name 'LegalNoticeCaption' -Value 'AUTHORIZED USE ONLY' -Type String -Id 'REG-Banner' -Area 'Policy' | Out-Null
    Set-CPReg -Path $pol -Name 'LegalNoticeText' -Type String -Id 'REG-BannerText' -Area 'Policy' `
        -Value 'This information system is the property of the organization and is provided for authorized use only. Unauthorized access, use, or modification is prohibited and may result in disciplinary, civil, and criminal penalties. All activity on this system is logged, monitored, and subject to audit.' | Out-Null
    Set-CPReg -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI' -Name 'EnumerateAdministrators' -Value 0 -Id 'REG-EnumAdmins' -Area 'UAC' | Out-Null

    # ---- explorer: hidden files + extensions (almost always scored) --------
    $advPaths = @(
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
    )
    foreach ($exu in $advPaths) {
        Set-CPReg -Path $exu -Name 'Hidden'          -Value 1 -Id 'REG-ShowHidden'      -Area 'Explorer' | Out-Null
        Set-CPReg -Path $exu -Name 'ShowSuperHidden' -Value 1 -Id 'REG-ShowSuperHidden' -Area 'Explorer' | Out-Null
        Set-CPReg -Path $exu -Name 'HideFileExt'     -Value 0 -Id 'REG-ShowExt'         -Area 'Explorer' | Out-Null
    }

    $exp = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
    Set-CPReg -Path $exp -Name 'NoDriveTypeAutoRun'   -Value 255 -Id 'REG-Autorun' -Area 'Registry' | Out-Null
    Set-CPReg -Path $exp -Name 'NoAutorun'            -Value 1 | Out-Null
    Set-CPReg -Path $exp -Name 'NoAutoplayfornonVolume' -Value 1 | Out-Null
    Set-CPReg -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -Value 255 | Out-Null

    $att = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments'
    Set-CPReg -Path $att -Name 'SaveZoneInformation'      -Value 2 -Id 'REG-ZoneInfo' -Area 'Registry' | Out-Null
    Set-CPReg -Path $att -Name 'HideZoneInfoOnProperties' -Value 1 | Out-Null
    Set-CPReg -Path $att -Name 'ScanWithAntiVirus'        -Value 3 -Id 'REG-AttachScan' -Area 'Registry' | Out-Null

    # ---- RDP: preserve its enabled/disabled state, enforce NLA if used -----
    $rdp    = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $rdpPol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    Set-CPReg -Path "$rdp\WinStations\RDP-Tcp" -Name 'UserAuthentication' -Value 1 -Id 'REG-RDP-NLA' -Area 'RDP' | Out-Null
    Set-CPReg -Path "$rdp\WinStations\RDP-Tcp" -Name 'SecurityLayer'      -Value 2 | Out-Null
    Set-CPReg -Path "$rdp\WinStations\RDP-Tcp" -Name 'MinEncryptionLevel' -Value 3 -Id 'REG-RDP-Enc' -Area 'RDP' | Out-Null
    Set-CPReg -Path $rdpPol -Name 'fPromptForPassword'    -Value 1 -Id 'REG-RDP-Prompt' -Area 'RDP' | Out-Null
    Set-CPReg -Path $rdpPol -Name 'MinEncryptionLevel'    -Value 3 | Out-Null
    Set-CPReg -Path $rdpPol -Name 'SecurityLayer'         -Value 2 | Out-Null
    Set-CPReg -Path $rdpPol -Name 'UserAuthentication'    -Value 1 | Out-Null
    if ($Aggressive -and $script:KeepList -notcontains 'TermService') {
        if (Confirm-CP 'AGGRESSIVE: fully disable RDP? Do NOT do this if the README lists remote access as a critical service.') {
            Set-CPReg -Path $rdp    -Name 'fDenyTSConnections' -Value 1 -Id 'REG-RDP-Deny' -Area 'RDP' | Out-Null
            Set-CPReg -Path $rdpPol -Name 'fDenyTSConnections' -Value 1 | Out-Null
        }
    } else {
        Add-Finding -Id 'REG-RDP-Deny' -Area 'RDP' -Status 'INFO' -Detail 'RDP connection state preserved (NLA + high encryption requested)' `
            -Hint 'Re-run with -Aggressive to fully disable RDP, once you have confirmed it is not a critical service in the README.'
    }

    # ---- WinRM ------------------------------------------------------------
    $wrS = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
    $wrC = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
    Set-CPReg -Path $wrS -Name 'AllowBasic'              -Value 0 -Id 'REG-WinRM-Basic' -Area 'Registry' | Out-Null
    Set-CPReg -Path $wrS -Name 'AllowUnencryptedTraffic' -Value 0 | Out-Null
    Set-CPReg -Path $wrS -Name 'DisableRunAs'             -Value 1 | Out-Null
    Set-CPReg -Path $wrC -Name 'AllowBasic'              -Value 0 | Out-Null
    Set-CPReg -Path $wrC -Name 'AllowUnencryptedTraffic' -Value 0 | Out-Null
    Set-CPReg -Path $wrC -Name 'AllowDigest'             -Value 0 | Out-Null

    # ---- SMB signing --------------------------------------------------------
    $srv  = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    $wkst = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
    Set-CPReg -Path $srv  -Name 'RequireSecuritySignature' -Value 1 -Id 'REG-SMBSign-Server' -Area 'SMB' | Out-Null
    Set-CPReg -Path $srv  -Name 'EnableSecuritySignature'  -Value 1 | Out-Null
    Set-CPReg -Path $wkst -Name 'EnableInsecureGuestLogons' -Value 0 -Id 'REG-GuestLogons' -Area 'SMB' | Out-Null
    Set-CPReg -Path $srv  -Name 'RestrictNullSessAccess' -Value 1 -Id 'REG-NullSession' -Area 'SMB' | Out-Null
    Set-CPReg -Path $srv  -Name 'NullSessionShares' -Value @('') -Type MultiString -Id 'REG-NullShares' -Area 'SMB' | Out-Null
    Set-CPReg -Path $srv  -Name 'NullSessionPipes'  -Value @('') -Type MultiString -Id 'REG-NullPipes'  -Area 'SMB' | Out-Null
    Set-CPReg -Path $wkst -Name 'RequireSecuritySignature' -Value 1 -Id 'REG-SMBSign-Client' -Area 'SMB' | Out-Null
    Set-CPReg -Path $wkst -Name 'EnableSecuritySignature'  -Value 1 | Out-Null
    Set-CPReg -Path $wkst -Name 'EnablePlainTextPassword'  -Value 0 -Id 'REG-PlainTextPw' -Area 'SMB' | Out-Null
    Set-CPReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' -Name 'AllowInsecureGuestAuth' -Value 0 | Out-Null

    # ---- RPC ----------------------------------------------------------------
    Set-CPReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\RPC' -Name 'RestrictRemoteClients'  -Value 1 -Id 'REG-RPC-Restrict' -Area 'Registry' | Out-Null
    Set-CPReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\RPC' -Name 'EnableAuthEpResolution' -Value 1 | Out-Null

    # ---- schannel: kill old TLS, enable 1.2/1.3 -------------------------------
    $sch = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
    foreach ($proto in @('SSL 2.0','SSL 3.0','TLS 1.0','TLS 1.1','PCT 1.0')) {
        Set-CPReg -Path "$sch\$proto\Server" -Name 'Enabled'           -Value 0 -Id "REG-TLS-$proto" -Area 'TLS' | Out-Null
        Set-CPReg -Path "$sch\$proto\Server" -Name 'DisabledByDefault' -Value 1 | Out-Null
        Set-CPReg -Path "$sch\$proto\Client" -Name 'Enabled'           -Value 0 | Out-Null
        Set-CPReg -Path "$sch\$proto\Client" -Name 'DisabledByDefault' -Value 1 | Out-Null
    }
    $modernTls = @('TLS 1.2')
    if ($build -ge 20348) { $modernTls += 'TLS 1.3' }
    foreach ($proto in $modernTls) {
        Set-CPReg -Path "$sch\$proto\Server" -Name 'Enabled'           -Value 1 | Out-Null
        Set-CPReg -Path "$sch\$proto\Server" -Name 'DisabledByDefault' -Value 0 | Out-Null
        Set-CPReg -Path "$sch\$proto\Client" -Name 'Enabled'           -Value 1 | Out-Null
        Set-CPReg -Path "$sch\$proto\Client" -Name 'DisabledByDefault' -Value 0 | Out-Null
    }
    Add-Finding -Id 'REG-CipherOrder' -Area 'TLS' -Status 'INFO' -Detail 'existing/default cipher order preserved' `
        -Hint 'Cipher availability depends on the OS and workload. Review Get-TlsCipherSuite before setting a supported, nonempty list; do not replace it with a cross-version static list.'
    foreach ($nd in @('HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319','HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319')) {
        Set-CPReg -Path $nd -Name 'SchUseStrongCrypto'       -Value 1 -Id 'REG-DotNetCrypto' -Area 'TLS' | Out-Null
        Set-CPReg -Path $nd -Name 'SystemDefaultTlsVersions' -Value 1 | Out-Null
    }

    # ---- powershell logging. graders love it, attackers hate it --------------
    $psl = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
    Set-CPReg -Path "$psl\ScriptBlockLogging" -Name 'EnableScriptBlockLogging'           -Value 1 -Id 'REG-PS-ScriptBlock' -Area 'Logging' | Out-Null
    Set-CPReg -Path "$psl\ScriptBlockLogging" -Name 'EnableScriptBlockInvocationLogging' -Value 1 | Out-Null
    Set-CPReg -Path "$psl\ModuleLogging"      -Name 'EnableModuleLogging'                -Value 1 -Id 'REG-PS-Module' -Area 'Logging' | Out-Null
    Set-CPReg -Path "$psl\ModuleLogging\ModuleNames" -Name '*' -Value '*' -Type String | Out-Null
    Set-CPReg -Path "$psl\Transcription" -Name 'EnableTranscripting'    -Value 1 -Id 'REG-PS-Transcript' -Area 'Logging' | Out-Null
    Set-CPReg -Path "$psl\Transcription" -Name 'EnableInvocationHeader' -Value 1 | Out-Null
    Set-CPReg -Path "$psl\Transcription" -Name 'OutputDirectory' -Value (Join-Path $script:Root 'pslogs') -Type String | Out-Null
    Invoke-CP 'private PowerShell transcript directory' { New-CPPrivateDirectory (Join-Path $script:Root 'pslogs') } | Out-Null

    # ---- smart screen + windows update policy + installer ---------------------
    Set-CPReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnableSmartScreen'     -Value 1 -Id 'REG-SmartScreen' -Area 'Registry' | Out-Null
    Set-CPReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'ShellSmartScreenLevel' -Value 'Block' -Type String | Out-Null
    Set-CPReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'NoAutoUpdate'  -Value 0 -Id 'REG-WU' -Area 'Updates' | Out-Null
    Set-CPReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'AUOptions'     -Value 4 | Out-Null
    Set-CPReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'AutoInstallMinorUpdates' -Value 1 | Out-Null
    Set-CPReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'AutomaticMaintenanceEnabled' -Value 1 | Out-Null
    Set-CPReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name 'DisableWindowsUpdateAccess' -Value 0 | Out-Null
    Set-CPReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name 'ElevateNonAdmins' -Value 0 | Out-Null
    Set-CPReg -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' -Name 'AUOptions' -Value 4 | Out-Null
    Set-CPReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client' -Name 'PreventAutoRun' -Value 1 -Id 'REG-Messenger' -Area 'Registry' | Out-Null
    Set-CPReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\SearchCompanion' -Name 'DisableContentFileUpdates' -Value 1 -Id 'REG-SearchCompanion' -Area 'Registry' | Out-Null
    Set-CPReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\IIS' -Name 'PreventIISInstall' -Value 1 -Id 'REG-IIS-Install' -Area 'Registry' | Out-Null
    Set-CPReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated' -Value 0 -Id 'REG-InstallerElevated' -Area 'Registry' | Out-Null
    Set-CPReg -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated' -Value 0 | Out-Null

    # ---- internet zones: protected mode + popup blocker -----------------------
    foreach ($zone in @('1','2','3','4')) {
        $z = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\$zone"
        Set-CPReg -Path $z -Name '2500' -Value 0 | Out-Null   # protected mode ON
        Set-CPReg -Path $z -Name '1809' -Value 0 | Out-Null   # pop-up blocker ON
        Set-CPReg -Path $z -Name '1609' -Value 0 | Out-Null   # warn on zone crossing
        Set-CPReg -Path $z -Name '1201' -Value 3 | Out-Null   # prompt unsigned ActiveX
        Set-CPReg -Path $z -Name '1400' -Value $(if ($zone -in '3','4') { 3 } else { 0 }) | Out-Null
        Set-CPReg -Path $z -Name '1A00' -Value $(if ($zone -in '3','4') { 65536 } else { 0 }) | Out-Null
    }

    # ---- crash dumps + removable media -------------------------------------
    Set-CPReg -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name 'CrashDumpEnabled' -Value 0 -Id 'REG-CrashDump' -Area 'Registry' | Out-Null
    Set-CPReg -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Cdrom' -Name 'AutoRun' -Value 0 -Id 'REG-CDRomAutorun' -Area 'Registry' | Out-Null

    # ---- Office macro hardening --------------------------------------------
    # patch all three policy hives; Office writes HKCU policy values, and the
    # exact version key depends on what the image has installed.
    $officeApps = [ordered]@{
        'word'       = @{ 'vbawarnings'=4; 'blockcontentexecutionfrominternet'=1; 'wordbypassencryptedmacroscan'=0 }
        'excel'      = @{ 'vbawarnings'=4; 'blockcontentexecutionfrominternet'=1; 'excelbypassencryptedmacroscan'=0 }
        'powerpoint' = @{ 'vbawarnings'=4; 'blockcontentexecutionfrominternet'=1 }
        'access'     = @{ 'vbawarnings'=4 }
        'publisher'  = @{ 'vbawarnings'=4 }
        'visio'      = @{ 'vbawarnings'=4; 'blockcontentexecutionfrominternet'=1 }
        'outlook'    = @{ 'level'=4 }
        'ms project' = @{ 'level'=4; 'vbawarnings'=4 }
    }
    $officeOk = $true
    foreach ($ver in @('16.0','15.0','14.0')) {
        foreach ($app in $officeApps.Keys) {
            $sec = "HKCU:\Software\Policies\Microsoft\office\$ver\$app\security"
            foreach ($v in $officeApps[$app].Keys) {
                if (-not (Set-CPReg -Path $sec -Name $v -Value $officeApps[$app][$v])) { $officeOk = $false }
            }
        }
        if (-not (Set-CPReg -Path "HKCU:\Software\Policies\Microsoft\office\$ver\common\security" -Name 'automationsecurity' -Value 3)) { $officeOk = $false }
    }
    Add-Finding -Id 'REG-OFFICE-MACROS' -Area 'Office' -Status $(if ($officeOk) {'PASS'} elseif ($script:Dry) {'SKIP'} else {'WARN'}) -Detail 'Office macro policy for the executing user: 14.0/15.0/16.0'

    # cmd/wmic/cscript restrictions are DANGEROUS on CP images -- the scoring
    # client and your own tooling use them. report, do not block.
    Add-Finding -Id 'REG-CMD-Block' -Area 'Registry' -Status 'INFO' -Detail 'cmd.exe / wmic / regedit restriction NOT applied' `
        -Hint 'If the README explicitly asks you to block script hosts, use AppLocker or SRP -- not a Deny ACE on cmd.exe. Denying cmd.exe locks you out of your own tooling.'

    # AppLocker without a policy is just a stopped service. report what exists
    # instead of pretending the AppIDSvc start type is an AppLocker control.
    try {
        $appidSvc = Get-CPService 'AppIDSvc'
        $appidType = if ($appidSvc) { Get-CPStartType 'AppIDSvc' } else { 'missing' }
        $applocker = $null
        try { $applocker = Get-AppLockerPolicy -Effective -ErrorAction Stop } catch {}
        $appLockerRules = 0
        if ($applocker) {
            foreach ($col in @($applocker.RuleCollections)) { $appLockerRules += @($col.Rules).Count }
        }
        if ($appLockerRules -gt 0) {
            Add-Finding -Id 'REG-AppLocker' -Area 'Registry' -Status 'PASS' -Detail "effective AppLocker policy present ($appLockerRules rules); AppIDSvc = $appidType"
        } else {
            Add-Finding -Id 'REG-AppLocker' -Area 'Registry' -Status 'INFO' -Detail "no effective AppLocker policy; AppIDSvc = $appidType" `
                -Hint 'Only build an AppLocker policy if the README asks for it. A half-written policy blocks your own tools.'
        }
    } catch {}
}
# ------------------------------------------------------------------------------
# LOLBin egress blocks. these binaries are routinely abused to download or
# beacon, and almost never need outbound access on a scored workstation.
# -NoLolbinBlocks exists because a lab image may run logon scripts.
# ------------------------------------------------------------------------------
function Get-CPLolbinPaths {
    $leaves = @(
        'mshta.exe','wmic.exe','certutil.exe','rundll32.exe','regsvr32.exe',
        'cscript.exe','wscript.exe','msiexec.exe','installutil.exe','regasm.exe',
        'regsvcs.exe','msbuild.exe','cmstp.exe','pcalua.exe','forfiles.exe',
        'hh.exe','ieexec.exe','presentationhost.exe','xwizard.exe',
        'runscripthelper.exe','scriptrunner.exe','SyncAppvPublishingServer.exe',
        'appvlp.exe','odbcconf.exe','extrac32.exe','expand.exe','makecab.exe',
        'replace.exe','esentutl.exe','nltest.exe','rpcping.exe','bitsadmin.exe',
        'certoc.exe','msdt.exe','sdclt.exe','wab.exe','wsreset.exe'
    )
    $roots = @($env:windir, "$env:windir\System32", "$env:windir\SysWOW64",
        "$env:windir\System32\wbem", "$env:windir\SysWOW64\wbem")
    foreach ($framework in @("$env:windir\Microsoft.NET\Framework", "$env:windir\Microsoft.NET\Framework64")) {
        if (Test-Path -LiteralPath $framework) { $roots += @(Get-ChildItem -LiteralPath $framework -Directory -Filter 'v*' -ErrorAction Stop | ForEach-Object { $_.FullName }) }
    }
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        foreach ($leaf in $leaves) {
            $exe = Join-Path $root $leaf
            if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { continue }
            $sha = [Security.Cryptography.SHA256]::Create()
            try { $hash = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($exe.ToLowerInvariant()))).Replace('-','').Substring(0,24) }
            finally { $sha.Dispose() }
            [pscustomobject]@{ Path=$exe; Name=("CP-LOL-" + $hash); DisplayName=("CP Block outbound - " + $exe) }
        }
    }
}

function Get-CPFirewallRuleScope {
    param($Rule, [string]$Program = 'Any')
    try {
        $filters = @(
            @{ Object=($Rule | Get-NetFirewallPortFilter -ErrorAction Stop); Values=@{Protocol=@('Any','256');LocalPort=@('Any');RemotePort=@('Any')} }
            @{ Object=($Rule | Get-NetFirewallAddressFilter -ErrorAction Stop); Values=@{LocalAddress=@('Any');RemoteAddress=@('Any')} }
            @{ Object=($Rule | Get-NetFirewallApplicationFilter -ErrorAction Stop); Values=@{Program=@($Program);Package=@('Any','')} }
            @{ Object=($Rule | Get-NetFirewallServiceFilter -ErrorAction Stop); Values=@{Service=@('Any')} }
            @{ Object=($Rule | Get-NetFirewallInterfaceFilter -ErrorAction Stop); Values=@{InterfaceAlias=@('Any')} }
            @{ Object=($Rule | Get-NetFirewallInterfaceTypeFilter -ErrorAction Stop); Values=@{InterfaceType=@('Any')} }
            @{ Object=($Rule | Get-NetFirewallSecurityFilter -ErrorAction Stop); Values=@{Authentication=@('NotRequired');Encryption=@('NotRequired');LocalUser=@('Any','');RemoteUser=@('Any','');RemoteMachine=@('Any','')} }
        )
        $restricted = $false
        foreach ($filter in $filters) {
            if (-not $filter.Object -or @($filter.Object).Count -ne 1) { return 'Unknown' }
            foreach ($key in $filter.Values.Keys) {
                if (-not $filter.Object.PSObject.Properties[$key]) { return 'Unknown' }
                $values = @($filter.Object.$key)
                if ($values.Count -gt 1 -or $filter.Values[$key] -notcontains [string]$filter.Object.$key) { $restricted = $true }
            }
        }
        if ($restricted) { return 'Restricted' }
        return 'Open'
    } catch { return 'Unknown' }
}

function Test-CPLolbinRule {
    param($Rule, [string]$Path)
    return ($null -ne $Rule -and "$($Rule.Enabled)" -eq 'True' -and
        "$($Rule.Direction)" -eq 'Outbound' -and "$($Rule.Action)" -eq 'Block' -and
        "$($Rule.Profile)" -eq 'Any' -and (Get-CPFirewallRuleScope $Rule $Path) -eq 'Open')
}

function Set-CPLolbinBlocks {
    if (-not (Test-CPMutation 'LOLBin outbound blocks')) { return 0 }
    $paths = @(Get-CPLolbinPaths)
    $script:LolbinExpected = $paths.Count
    $count = 0
    foreach ($item in $paths) {
        try {
            $existing = Get-NetFirewallRule -Name $item.Name -ErrorAction SilentlyContinue
            if (-not (Test-CPLolbinRule $existing $item.Path)) {
                if ($existing) { Remove-NetFirewallRule -Name $item.Name -ErrorAction Stop }
                New-NetFirewallRule -Name $item.Name -DisplayName $item.DisplayName -Direction Outbound -Program $item.Path `
                    -Action Block -Profile Any -Enabled True -ErrorAction Stop | Out-Null
            }
            if (-not (Test-CPLolbinRule (Get-NetFirewallRule -Name $item.Name -ErrorAction Stop) $item.Path)) { throw 'rule properties could not be verified' }
            $count++
        } catch { Add-Review "LOLBin block not verified for $($item.Path): $($_.Exception.Message)" }
    }
    return $count
}

# ------------------------------------------------------------------------------
# network: firewall, smb, tcp/ip
# ------------------------------------------------------------------------------
function Invoke-Network {
    Write-Banner 'NETWORK / FIREWALL / SMB'
    if (-not (Enter-CPPhase 'network' -Mutating)) { return }

    Invoke-CP 'firewall profiles on, inbound blocked by default' {
        foreach ($fwProfile in @('Domain','Private','Public')) {
            # Do not replace a stronger existing outbound Block policy with Allow.
            Set-NetFirewallProfile -Profile $fwProfile -Enabled True -DefaultInboundAction Block `
                -LogBlocked True -NotifyOnListen True -ErrorAction Stop
            $state = Get-NetFirewallProfile -Profile $fwProfile -ErrorAction Stop
            if ("$($state.Enabled)" -ne 'True' -or $state.DefaultInboundAction -ne 'Block') { throw "firewall profile not enforced: $fwProfile" }
        }
    }
    if ($FirewallFile) {
        if (Test-Path -LiteralPath $FirewallFile -PathType Leaf) {
            $fwOk = Invoke-CP ("import local firewall policy " + $FirewallFile) {
                $null = Assert-CPNoReparse $FirewallFile
                if (-not (Confirm-CP 'Import this firewall policy, replacing current rules and profile defaults?' -InteractiveOnly)) { throw 'firewall import left for review' }
                Invoke-CPNative netsh.exe @('advfirewall','import',$FirewallFile) | Out-Null
            }
            if ($fwOk) {
                Add-Finding -Id 'FW-IMPORT' -Area 'Firewall' -Status 'PASS' -Detail "imported local policy: $FirewallFile"
            } elseif ($script:Dry) {
                Add-Finding -Id 'FW-IMPORT' -Area 'Firewall' -Status 'INFO' -Detail "would import local policy: $FirewallFile"
            } else {
                Add-Finding -Id 'FW-IMPORT' -Area 'Firewall' -Status 'WARN' -Detail "could not import local policy: $FirewallFile" `
                    -Hint 'Check the file format and that Windows Firewall is running. netsh advfirewall import expects a .wfw file.'
            }
        } else {
            Add-Finding -Id 'FW-IMPORT' -Area 'Firewall' -Status 'WARN' -Detail "firewall file not found: $FirewallFile" `
                -Hint 'Pass a local .wfw file you trust. The script deliberately does not download firewall policies.'
        }
    }

    foreach ($p in @('Domain','Private','Public')) {
        try {
            $f = Get-NetFirewallProfile -Profile $p -ErrorAction Stop
            $good = ("$($f.Enabled)" -eq 'True') -and ($f.DefaultInboundAction -eq 'Block')
            Add-Finding -Id "FW-$p" -Area 'Firewall' -Status $(if ($good) {'PASS'} else {'FAIL'}) `
                -Detail "$p enabled=$($f.Enabled) defaultInbound=$($f.DefaultInboundAction)"
        } catch {
            Add-Finding -Id "FW-$p" -Area 'Firewall' -Status 'WARN' -Detail "$p effective firewall profile query unavailable"
        }
    }

    Invoke-CP 'firewall logging' {
        New-CPPrivateDirectory (Join-Path $script:Root 'fwlogs')
        foreach ($p in @('Domain','Private','Public')) {
            Set-NetFirewallProfile -Profile $p -LogFileName (Join-Path $script:Root 'fwlogs\pfirewall.log') `
                -LogMaxSizeKilobytes 16384 -ErrorAction Stop
        }
    }

    # ---- LOLBin egress blocks ------------------------------------------------
    if ($NoLolbinBlocks) {
        Add-Finding -Id 'FW-LOLBIN' -Area 'Firewall' -Status 'SKIP' -Detail 'LOLBin outbound blocks skipped (-NoLolbinBlocks)' `
            -Hint 'Only skip this if a logon script or scoring client actually needs wscript/mshta/certutil egress.'
    } else {
        $script:LolbinCount = 0
        Invoke-CP 'LOLBin outbound blocks' {
            $script:LolbinCount = Set-CPLolbinBlocks
        } | Out-Null
        if ($script:Dry) {
            Add-Finding -Id 'FW-LOLBIN' -Area 'Firewall' -Status 'INFO' -Detail 'LOLBin outbound blocks would be created'
        } elseif ([int]$script:LolbinCount -gt 0 -and $script:LolbinCount -eq $script:LolbinExpected) {
            Add-Finding -Id 'FW-LOLBIN' -Area 'Firewall' -Status 'PASS' -Detail "$([int]$script:LolbinCount) LOLBin outbound block rule(s) present"
        } else {
            Add-Finding -Id 'FW-LOLBIN' -Area 'Firewall' -Status 'WARN' -Detail 'could not create LOLBin outbound block rules' `
                -Hint 'Check that the Windows Firewall service is running and that you are elevated.'
        }
    }

    # ---- Remote Assistance ---------------------------------------------------
    Invoke-CP 'Remote Assistance off' {
        Set-CPReg -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' `
            -Name 'fAllowToGetHelp' -Value 0 -Id 'NET-RA' -Area 'RemoteAccess' | Out-Null
        Set-CPReg -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' `
            -Name 'fAllowFullControl' -Value 0 | Out-Null
        Set-CPReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' `
            -Name 'fAllowToGetHelp' -Value 0 | Out-Null
        Set-CPReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' `
            -Name 'fEncryptRPCTraffic' -Value 1 | Out-Null
    } | Out-Null

    # wide-open inbound allow rules defeat the whole firewall. rules with no
    # display group are usually hand-made -- the sneaky ones live there.
    $script:PermissiveFwRules = @()
    Invoke-CP -ReadOnly 'permissive inbound rule scan' {
        $bad = @()
        $unknown = 0
        try {
            $rules = @(Get-NetFirewallRule -ErrorAction Stop | Where-Object {
                $_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow'
            })
            foreach ($r in $rules) {
                $scope = Get-CPFirewallRuleScope $r
                if ($scope -eq 'Unknown') { $unknown++ }
                if ($scope -eq 'Open') {
                    $bad += [pscustomobject]@{ Name=$r.Name; DisplayName=$r.DisplayName; Profile=$r.Profile }
                }
            }
        } catch { $unknown++; Write-CP ("could not enumerate firewall rules: " + $_.Exception.Message) 'warn' }
        $bad | Export-Csv (Join-Path $script:EvDir 'firewall-permissive.csv') -NoTypeInformation
        $script:PermissiveFwRules = @($bad)
        if ($bad.Count -gt 0) {
            Add-Finding -Id 'FW-PERMISSIVE' -Area 'Firewall' -Status 'FAIL' -Detail "$($bad.Count) allow-ALL-inbound rule(s)" `
                -Hint 'An "allow all inbound" rule defeats the whole firewall. Delete it unless the README demands it.'
            foreach ($b in $bad) { Write-Host ("     - {0}" -f $b.Name) -ForegroundColor DarkYellow }
            $keepManagement = @($script:KeepList | Where-Object { $_ -in 'WinRM','TermService','RemoteAccess','sshd' }).Count -gt 0
            if ($keepManagement) { Add-Review 'wide-open firewall rules preserved because a management service is explicitly kept; scope replacement allow rules manually' }
        } else {
            Add-Finding -Id 'FW-PERMISSIVE' -Area 'Firewall' -Status $(if ($unknown) {'WARN'} else {'PASS'}) -Detail "no confirmed allow-all inbound rules; unknown filters=$unknown"
        }
    }
    if ($script:PermissiveFwRules.Count -gt 0 -and $Aggressive) {
        $keepManagement = @($script:KeepList | Where-Object { $_ -in 'WinRM','TermService','RemoteAccess','sshd' }).Count -gt 0
        if (-not $keepManagement -and (Confirm-CP "AGGRESSIVE: disable $($script:PermissiveFwRules.Count) wide-open inbound allow rule(s)?" -InteractiveOnly)) {
            foreach ($b in $script:PermissiveFwRules) {
                Invoke-CP ("disable firewall rule " + $b.Name) {
                    Disable-NetFirewallRule -Name $b.Name -ErrorAction Stop
                    if ("$((Get-NetFirewallRule -Name $b.Name -ErrorAction Stop).Enabled)" -ne 'False') { throw 'rule still enabled' }
                } | Out-Null
            }
        }
    }

    # inventory every enabled inbound allow rule, not only the wide-open ones.
    # hand-made rules with no display group are where backdoors usually hide.
    Invoke-CP -ReadOnly 'inbound allow rule inventory' {
        try {
            $allow = @(Get-NetFirewallRule -ErrorAction Stop | Where-Object {
                $_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow'
            } | Select-Object DisplayName,Profile,DisplayGroup,Group)
            $allow | Export-Csv (Join-Path $script:EvDir 'firewall-inbound-allow.csv') -NoTypeInformation
            $custom = @($allow | Where-Object { -not $_.DisplayGroup -and -not $_.Group })
            if ($custom.Count -gt 0) {
                Add-Finding -Id 'FW-CUSTOM' -Area 'Firewall' -Status 'WARN' -Detail "$($custom.Count) inbound allow rule(s) with no display group" `
                    -Hint 'Review firewall-inbound-allow.csv. A hand-made allow rule is a common persistence/backdoor. Disable only rules the README does not require.'
            } else {
                Add-Finding -Id 'FW-CUSTOM' -Area 'Firewall' -Status 'PASS' -Detail 'no ungrouped inbound allow rules'
            }
        } catch {
            Add-Finding -Id 'FW-CUSTOM' -Area 'Firewall' -Status 'WARN' -Detail 'could not inventory inbound allow rules'
        }
    }

    # SMBv1 -- always safe to kill
    Invoke-CP 'SMBv1 disable' {
        $f = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
        if ($f -and $f.State -eq 'Enabled') {
            Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
        }
        try { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop } catch {}
        Set-CPReg 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1' 0 | Out-Null
    }
    try {
        $f = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
        $smb1Cfg = $null
        try { $smb1Cfg = (Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol } catch {}
        $smb1Reg = Get-CPReg -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'SMB1'
        $smb1Off = ($f.State -ne 'Enabled') -and
            ($null -eq $smb1Cfg -or $smb1Cfg -eq $false) -and
            ($null -eq $smb1Reg -or "$smb1Reg" -eq '0')
        Add-Finding -Id 'SMB-V1' -Area 'SMB' -Status $(if ($smb1Off) {'PASS'} else {'FAIL'}) `
            -Detail "SMB1Protocol=$($f.State); EnableSMB1Protocol=$(if ($null -eq $smb1Cfg) {'unavailable'} else {$smb1Cfg}); registry SMB1=$(if ($null -eq $smb1Reg) {'absent'} else {$smb1Reg})" `
            -Hint $(if ($smb1Off) {''} else {'Disable SMB1 in Windows Features and run: Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force.'})
    } catch { Add-Finding -Id 'SMB-V1' -Area 'SMB' -Status 'WARN' -Detail 'SMBv1 disable attempted (query unavailable)' -Hint 'Verify with Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol and Get-SmbServerConfiguration.' }

    Invoke-CP 'SMB signing enforcement' {
        try {
            Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true `
                -AutoDisconnect 15 -Force -ErrorAction Stop
            $smb = Get-SmbServerConfiguration -ErrorAction Stop
            if ($smb.RequireSecuritySignature -eq $true) {
                Add-Finding -Id 'SMB-SIGN' -Area 'SMB' -Status 'PASS' -Detail 'SMB signing required on server (verified)'
            } else {
                Add-Finding -Id 'SMB-SIGN' -Area 'SMB' -Status 'WARN' -Detail 'SMB signing command succeeded but RequireSecuritySignature is false' `
                    -Hint 'Check Get-SmbServerConfiguration; a domain GPO may override the local setting.'
            }
        } catch {
            Add-Finding -Id 'SMB-SIGN' -Area 'SMB' -Status 'WARN' -Detail 'Set-SmbServerConfiguration unavailable' `
                -Hint 'The registry equivalents were set in the registry section; verify with Get-SmbServerConfiguration.'
        }
        try { Set-SmbClientConfiguration -RequireSecuritySignature $true -EnableInsecureGuestLogons $false -Force -ErrorAction Stop } catch {}
    }

    # TCP/IP stack hardening
    $tcp = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
    Set-CPReg -Path $tcp -Name 'DisableIPSourceRouting' -Value 2 -Id 'NET-SourceRoute'  -Area 'Network' | Out-Null
    Set-CPReg -Path $tcp -Name 'EnableICMPRedirect'     -Value 0 -Id 'NET-ICMPRedirect' -Area 'Network' | Out-Null
    Set-CPReg -Path $tcp -Name 'SynAttackProtect'       -Value 1 -Id 'NET-SynFlood'     -Area 'Network' | Out-Null
    Set-CPReg -Path $tcp -Name 'KeepAliveTime'          -Value 300000 | Out-Null
    Set-CPReg -Path $tcp -Name 'IPEnableRouter'         -Value 0 -Id 'NET-IPForward'    -Area 'Network' | Out-Null
    Set-CPReg -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name 'DisableIPSourceRouting' -Value 2 | Out-Null

    # LLMNR off (name-resolution spoofing surface)
    Set-CPReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name 'EnableMulticast' -Value 0 -Id 'NET-LLMNR' -Area 'Network' | Out-Null

    # NetBIOS / admin shares -- aggressive only, some scoring uses WINS names
    if ($Aggressive) {
        Invoke-CP 'NetBIOS over TCP/IP off' {
            foreach ($a in @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction Stop)) {
                $r = Invoke-CimMethod -InputObject $a -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = [uint32]2 } -ErrorAction Stop
                if ($r.ReturnValue -ne 0) { throw "SetTcpipNetbios failed for $($a.Description) (return $($r.ReturnValue))" }
            }
            if (-not (Set-CPReg 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' 'NetbiosOptions' 2)) {
                throw 'could not set the NetBT NetbiosOptions registry value'
            }
            $nbLeft = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction Stop |
                Where-Object { $_.TcpipNetbiosOptions -ne 2 })
            for ($i = 0; $i -lt 5 -and $nbLeft.Count -gt 0; $i++) {
                Start-Sleep -Milliseconds 300
                $nbLeft = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction Stop |
                    Where-Object { $_.TcpipNetbiosOptions -ne 2 })
            }
            if ($nbLeft.Count -gt 0) {
                throw ("NetBIOS still enabled on: " + (($nbLeft | ForEach-Object { $_.Description }) -join '; '))
            }
            Add-Finding -Id 'NET-NETBIOS' -Area 'Network' -Status 'PASS' -Detail 'NetBIOS over TCP/IP disabled and verified on all adapters'
        } | Out-Null
        Invoke-CP 'admin shares off (C$ / ADMIN$)' {
            Set-CPReg 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'AutoShareWks'    0 -Id 'SMB-AdminShare' -Area 'SMB' | Out-Null
            Set-CPReg 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'AutoShareServer' 0 | Out-Null
        } | Out-Null
    } else {
        Add-Finding -Id 'NET-NETBIOS' -Area 'Network' -Status 'INFO' -Detail 'NetBIOS left as-is' `
            -Hint 'Run with -Aggressive to disable NetBIOS over TCP/IP. Check the README first if the box is a file server or a DC.'
    }

    $script:WinRmHttp = $false
    Invoke-CP -ReadOnly 'WinRM listener check' {
        $l = @(Invoke-CPNative winrm.exe @('enumerate','winrm/config/listener') -ReadOnly) -join "`n"
        $script:WinRmHttp = [bool]($l -match '(?im)^[ \t]*Transport[ \t]*=[ \t]*HTTP[ \t]*$')
        if ($script:WinRmHttp) {
            Add-Finding -Id 'NET-WinRM' -Area 'Network' -Status 'WARN' -Detail 'WinRM HTTP listener present' `
                -Hint 'HTTP WinRM (5985) is unencrypted. Remove it unless remote management is a stated critical service.'
        } elseif ($l -match '(?im)^[ \t]*Transport[ \t]*=[ \t]*HTTPS[ \t]*$') {
            Add-Finding -Id 'NET-WinRM' -Area 'Network' -Status 'PASS' -Detail 'WinRM has an HTTPS listener only'
        } else {
            Add-Finding -Id 'NET-WinRM' -Area 'Network' -Status 'PASS' -Detail 'no WinRM listener found'
        }
    }
    if ($script:WinRmHttp -and $Aggressive) {
        Invoke-CP 'remove HTTP WinRM listener' {
            Invoke-CPNative winrm.exe @('delete','winrm/config/listener?Address=*+Transport=HTTP') | Out-Null
            $after = @(Invoke-CPNative winrm.exe @('enumerate','winrm/config/listener') -ReadOnly) -join "`n"
            if ($after -match '(?im)^[ \t]*Transport[ \t]*=[ \t]*HTTP[ \t]*$') { throw 'HTTP WinRM listener still present' }
            Add-Finding -Id 'NET-WinRM' -Area 'Network' -Status 'PASS' -Detail 'HTTP WinRM listener removed'
        } | Out-Null
    }

    if ($Aggressive) {
        if (Confirm-CP 'AGGRESSIVE: disable PowerShell Remoting (Disable-PSRemoting)? This can break remote management and the scoring client if it uses WinRM.') {
            $psrDone = Invoke-CP 'disable PowerShell Remoting' {
                Disable-PSRemoting -Force -ErrorAction Stop
            }
            if ($psrDone) {
                Add-Finding -Id 'NET-PSREMOTING' -Area 'Network' -Status 'PASS' -Detail 'PowerShell Remoting disabled'
            } else {
                Add-Finding -Id 'NET-PSREMOTING' -Area 'Network' -Status 'WARN' -Detail 'could not disable PowerShell Remoting' `
                    -Hint 'Check the OPERATION finding; WinRM may be managed by policy. Verify with Get-PSSessionConfiguration.'
            }
        } else {
            Add-Finding -Id 'NET-PSREMOTING' -Area 'Network' -Status 'SKIP' -Detail 'PowerShell Remoting left enabled by operator'
        }
    } else {
        Add-Finding -Id 'NET-PSREMOTING' -Area 'Network' -Status 'INFO' -Detail 'PowerShell Remoting left enabled' `
            -Hint 'Re-run with -Aggressive only if the README confirms remote PowerShell is not a critical service.'
    }
}

# ------------------------------------------------------------------------------
# services. safe tier is basically always fine. aggressive tier can be THE
# critical service of the round -- read the README first.
# ------------------------------------------------------------------------------
function Disable-CPService {
    param($svc)
    $n = $svc.n
    if ($script:KeepList -contains $n) { Write-CP "skip $n (in keep list)" 'info'; return }
    $s = Get-CPService $n
    if (-not $s) { return }
    $before = "$($s.Status)/$(Get-CPStartType $n)"
    $completed = Invoke-CP "stop + disable service '$n' ($($svc.why))" {
        Stop-Service -Name $n -Force -ErrorAction SilentlyContinue
        if (-not (Set-CPStartType -Name $n -Type 'Disabled')) { throw 'could not set start type' }
        $after = $null
        for ($i = 0; $i -lt 10; $i++) {
            $after = Get-CPService $n
            if (-not $after -or $after.Status -eq 'Stopped') { break }
            Start-Sleep -Milliseconds 500
        }
        if ($after -and $after.Status -ne 'Stopped') { throw "service is still $($after.Status)" }
    }
    if (-not $completed) {
        Add-Finding -Id "SVC-$n" -Area 'Services' -Status 'WARN' -Detail "$n not changed (was $before)"
        return
    }
    Add-Finding -Id "SVC-$n" -Area 'Services' -Status 'PASS' -Detail "$n disabled (was $before)"
    Register-Change -What "Service $n" -Old $before -New 'Stopped/Disabled'
}

function Invoke-Services {
    Write-Banner 'SERVICES'
    if (-not (Enter-CPPhase 'services' -Mutating)) { return }

    $safeOff = @(
        @{n='RemoteRegistry';     why='remote registry access'},
        @{n='TlntSvr';            why='Telnet server'},
        @{n='telnet';             why='Telnet server'},
        @{n='Fax';                why='Fax service'},
        @{n='RpcLocator';         why='legacy RPC locator'},
        @{n='WMPNetworkSvc';      why='WMP network sharing'},
        @{n='SSDPSRV';            why='SSDP/UPnP discovery'},
        @{n='upnphost';           why='UPnP device host'},
        @{n='Simptcp';            why='Simple TCP/IP services (echo/chargen)'},
        @{n='MNMSRVC';            why='NetMeeting remote desktop sharing'},
        @{n='SharedAccess';       why='Internet Connection Sharing'},
        @{n='icssvc';             why='Windows Mobile Hotspot'},
        @{n='lfsvc';              why='Geolocation'},
        @{n='RetailDemo';         why='Retail demo'},
        @{n='XblAuthManager';     why='Xbox Live auth'},
        @{n='XblGameSave';        why='Xbox Live game save'},
        @{n='XboxNetApiSvc';      why='Xbox Live networking'},
        @{n='XboxGipSvc';         why='Xbox accessory management'},
        @{n='DiagTrack';          why='Connected User Experiences and Telemetry'},
        @{n='dmwappushservice';   why='WAP push message routing'},
        @{n='MapsBroker';         why='Downloaded Maps Manager'},
        @{n='WpcMonSvc';          why='Parental controls'}
    )

    # obsolete names from older images. kept out of the safe list above only
    # because they are easy to confuse with services an app still needs.
    $legacyOff = @(
        @{n='ALG';          why='Application Layer Gateway (deprecated)'},
        @{n='Browser';      why='Computer Browser (legacy NetBIOS browsing)'},
        @{n='ClipSrv';      why='ClipBook (legacy)'},
        @{n='dmadmin';      why='Logical Disk Manager administrative service'},
        @{n='ERSvc';        why='Error Reporting Service (legacy)'},
        @{n='Messenger';    why='Net Send messenger (legacy)'},
        @{n='RSoPProv';     why='Resultant Set of Policy provider (legacy)'},
        @{n='TrkWks';       why='Distributed Link Tracking Client'},
        @{n='WmdmPmSN';     why='Portable Device Enumerator'},
        @{n='lltdsvc';      why='Link-Layer Topology Discovery'},
        @{n='iprip';        why='RIP Listener (legacy)'},
        @{n='nfsclnt';      why='NFS client (legacy)'},
        @{n='nfssvc';       why='NFS server (legacy)'},
        @{n='p2pimsvc';     why='Peer Networking Identity Manager'},
        @{n='uploadmgr';    why='Upload Manager'}
    )

    $aggOff = @(
        @{n='FTPSVC';      why='IIS FTP server'},
        @{n='SNMP';        why='SNMP service'},
        @{n='SNMPTRAP';    why='SNMP trap'},
        @{n='WinRM';       why='Windows Remote Management'},
        @{n='TermService'; why='Remote Desktop Services'},
        @{n='SessionEnv';  why='Remote Desktop Configuration (RDP dependency)'},
        @{n='UmRdpService'; why='RDP UserMode Port Redirector (RDP dependency)'},
        @{n='RemoteAccess'; why='Routing and Remote Access / VPN'},
        @{n='PolicyAgent'; why='IPSec Policy Agent (domain traffic)'},
        @{n='W3SVC';       why='IIS web server'},
        @{n='WAS';         why='Windows Process Activation Service'},
        @{n='SMTPSVC';     why='IIS SMTP'},
        @{n='MSSQLSERVER'; why='SQL Server default instance'},
        @{n='SQLBrowser';  why='SQL Server Browser'},
        @{n='DNS';         why='Windows DNS Server'}
    )

    $mustOn = @(
        @{n='WinDefend';             st='Automatic'; why='Defender service'},
        @{n='wuauserv';              st='Automatic'; why='Windows Update'},
        @{n='BITS';                  st='Automatic'; why='background transfer'},
        @{n='EventLog';              st='Automatic'; why='event log'},
        @{n='MpsSvc';                st='Automatic'; why='Windows Firewall'},
        @{n='BFE';                   st='Automatic'; why='Base Filtering Engine (firewall dependency)'},
        @{n='Schedule';              st='Automatic'; why='Task Scheduler'},
        @{n='Winmgmt';               st='Automatic'; why='WMI'},
        @{n='W32Time';               st='Automatic'; why='time sync'},
        @{n='AppIDSvc';              st='Manual';    why='AppLocker'},
        @{n='SecurityHealthService'; st='Manual';    why='Defender UI'},
        @{n='LanmanServer';          st='Automatic'; why='SMB server (often a critical service)'},
        @{n='LanmanWorkstation';     st='Automatic'; why='SMB client'},
        @{n='Dnscache';              st='Automatic'; why='DNS client'}
    )

    foreach ($s in $safeOff) { Disable-CPService -svc $s }
    foreach ($s in $legacyOff) { Disable-CPService -svc $s }

    if ($Aggressive) {
        Write-CP 'aggressive tier: these are frequently THE critical service' 'warn'
        foreach ($s in $aggOff) {
            $svc = Get-CPService $s.n
            if (-not $svc) { continue }
            if ((Get-CPStartType $s.n) -eq 'Disabled') { continue }
            if (Confirm-CP "AGGRESSIVE: disable '$($s.n)' ($($s.why))? If the README calls it critical, say NO.") {
                Disable-CPService -svc $s
            } else {
                Add-Finding -Id "SVC-$($s.n)" -Area 'Services' -Status 'SKIP' -Detail "$($s.n) left running by operator"
            }
        }
    } else {
        Add-Finding -Id 'SVC-AGG' -Area 'Services' -Status 'INFO' -Detail 'web/db/FTP/DNS services left alone' `
            -Hint 'Re-run with -Aggressive if the README confirms none are critical. Otherwise HARDEN their config instead of stopping them.'
    }

    # things that must be running for a healthy, scorable image
    foreach ($m in $mustOn) {
        $s = Get-CPService $m.n
        if (-not $s) { continue }
        Invoke-CP "ensure '$($m.n)' is $($m.st)" {
            $cur = Get-CPStartType $m.n
            if ($cur -ne $m.st) { [void](Set-CPStartType -Name $m.n -Type $m.st) }
            if ($s.Status -ne 'Running' -and $m.st -eq 'Automatic') { Start-Service -Name $m.n -ErrorAction Stop }
        } | Out-Null
        $now = Get-CPService $m.n
        $nt  = Get-CPStartType $m.n
        $good = $false
        if ($now) {
            if ($m.st -eq 'Manual') {
                $good = ($nt -eq 'Manual')
            } else {
                $good = ($nt -eq $m.st -and $now.Status -eq 'Running')
            }
        }
        Add-Finding -Id "SVC-ON-$($m.n)" -Area 'Services' -Status $(if ($good) {'PASS'} else {'WARN'}) `
            -Detail "$($m.n) = $($now.Status)/$nt (want $($m.st))" `
            -Hint $(if ($good) {''} else {"A dead $($m.why) is worth more than ten registry keys. sc.exe start $($m.n)"})
    }

    # crash recovery so a service does not just stay dead
    Invoke-CP 'service failure recovery on must-run services' {
        foreach ($n in @('WinDefend','MpsSvc','BFE','EventLog','wuauserv','BITS','Schedule','Winmgmt')) {
            $null = & sc.exe failure $n reset= 86400 actions= restart/60000/restart/60000/restart/60000 2>&1
        }
    }
}
# ------------------------------------------------------------------------------
# defender + audit + updates
# ------------------------------------------------------------------------------
function Invoke-Defender {
    Write-Banner 'DEFENDER / AUDIT / UPDATES'
    if (-not (Enter-CPPhase 'defender' -Mutating)) { return }

    Invoke-CP 'defender service re-enabled' {
        $s = Get-CPService 'WinDefend'
        if ($s -and (Get-CPStartType 'WinDefend') -eq 'Disabled') {
            [void](Set-CPStartType -Name 'WinDefend' -Type 'Automatic')
            Start-Service WinDefend -ErrorAction SilentlyContinue
        }
        $s = Get-CPService 'WinDefend'
        $st = if ($s) { Get-CPStartType 'WinDefend' } else { 'missing' }
        if (-not $s) {
            Add-Finding -Id 'DEF-SVC' -Area 'Defender' -Status 'FAIL' -Detail 'WinDefend service not found' `
                -Hint 'Defender may have been removed or replaced by another AV product on this image.'
        } elseif ($s.Status -eq 'Running' -and $st -ne 'Disabled') {
            Add-Finding -Id 'DEF-SVC' -Area 'Defender' -Status 'PASS' -Detail "WinDefend = $($s.Status)/$st"
        } else {
            Add-Finding -Id 'DEF-SVC' -Area 'Defender' -Status 'WARN' -Detail "WinDefend = $($s.Status)/$st" `
                -Hint 'Start the service and set it to Automatic. A disabled WinDefend is a common way AV gets switched off.'
        }
    }

    # a policy key can silently switch Defender off -- clear it first
    Invoke-CP 'clear Defender-disabling policy values' {
        $pk = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
        Remove-ItemProperty -Path $pk -Name 'DisableAntiSpyware' -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $pk -Name 'DisableAntiVirus'   -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path "$pk\Real-Time Protection" -Name 'DisableRealtimeMonitoring' -ErrorAction SilentlyContinue
    }

    Invoke-CP 'defender sandbox + policy values' {
        $sandboxOk = $true
        [Environment]::SetEnvironmentVariable('MP_FORCE_USE_SANDBOX','1','Machine')
        if ([Environment]::GetEnvironmentVariable('MP_FORCE_USE_SANDBOX','Machine') -ne '1') { $sandboxOk = $false }
        $dp = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
        $sandboxValues = @(
            @{ Path=$dp; Name='DisableAntiSpyware'; Value=0 }
            @{ Path=$dp; Name='DisableAntiVirus'; Value=0 }
            @{ Path=$dp; Name='ServiceKeepAlive'; Value=1 }
            @{ Path="$dp\Real-Time Protection"; Name='DisableRealtimeMonitoring'; Value=0 }
            @{ Path="$dp\Real-Time Protection"; Name='DisableIOAVProtection'; Value=0 }
            @{ Path="$dp\Real-Time Protection"; Name='DisableBehaviorMonitoring'; Value=0 }
            @{ Path="$dp\Real-Time Protection"; Name='DisableScriptScanning'; Value=0 }
            @{ Path="$dp\Real-Time Protection"; Name='DisableArchiveScanning'; Value=0 }
            @{ Path="$dp\Real-Time Protection"; Name='DisableRemovableDriveScanning'; Value=0 }
            @{ Path="$dp\Real-Time Protection"; Name='DisableEmailScanning'; Value=0 }
            @{ Path="$dp\Scan"; Name='CheckForSignaturesBeforeRunningScan'; Value=1 }
            @{ Path="$dp\Scan"; Name='DisableHeuristics'; Value=0 }
            @{ Path="$dp\Signature Updates"; Name='ForceUpdateFromMU'; Value=1 }
        )
        foreach ($v in $sandboxValues) {
            if (-not (Set-CPReg -Path $v.Path -Name $v.Name -Value $v.Value)) { $sandboxOk = $false }
        }
        if ($sandboxOk) {
            Add-Finding -Id 'DEF-SANDBOX' -Area 'Defender' -Status 'PASS' -Detail 'Defender sandbox + policy values set'
        } else {
            Add-Finding -Id 'DEF-SANDBOX' -Area 'Defender' -Status 'WARN' -Detail 'one or more Defender policy values could not be verified' `
                -Hint 'Re-run the defender section, then inspect HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender and its subkeys.'
        }
    } | Out-Null

    Invoke-CP 'defender preferences (realtime/behavior/PUA/MAPS)' {
        Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false `
            -DisableIOAVProtection $false -DisableScriptScanning $false -DisableArchiveScanning $false `
            -DisableRemovableDriveScanning $false -DisableEmailScanning $false `
            -MAPSReporting Advanced -SubmitSamplesConsent SendSafeSamples `
            -PUAProtection Enabled -ErrorAction Stop
    }

    try {
        $pref = Get-MpPreference -ErrorAction Stop
        $prefOn = (-not $pref.DisableRealtimeMonitoring) -and (-not $pref.DisableBehaviorMonitoring) -and
                  (-not $pref.DisableIOAVProtection) -and (-not $pref.DisableScriptScanning)
        Add-Finding -Id 'DEF-PREF' -Area 'Defender' -Status $(if ($prefOn) {'PASS'} else {'FAIL'}) `
            -Detail "realtime=$(-not $pref.DisableRealtimeMonitoring) behavior=$(-not $pref.DisableBehaviorMonitoring) ioav=$(-not $pref.DisableIOAVProtection) script=$(-not $pref.DisableScriptScanning)"
    } catch {}

    # ASR rules -- the highest-value Defender block. worth trying even on
    # older platforms; unsupported IDs just no-op.
    Invoke-CP 'attack surface reduction rules + network protection' {
        $invalid = @('f8af271c-8ba8-4675-93ea-a397138fd05f','d4d940ab-c68b-4323-a2a4-93c78570f7d0')
        $asr = [ordered]@{
            '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' = 1   # office code injection
            '3b576869-a4ec-4529-8536-b80a7769e899' = 1   # office macros calling win32
            'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = 1   # office child processes
            '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' = 1   # win32 from office macros
            'd3e037e1-3eb8-44c8-a917-57927947596d' = 1   # js/vbs/ps launching exes
            '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = 1   # obfuscated scripts
            'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = 1   # executable from email/webmail
            '01443614-cd74-433a-b99e-2ecdc07bfc25' = 1   # office creating executables
            'c1db55ab-c21a-4637-bb3f-a12568109d35' = 1   # ransomware protection
            '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 1   # credential stealing from lsass
            'd1e49aac-8f56-4280-b9ba-993a6d77406c' = 1   # psexec/wmi process creation
            'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' = 1   # untrusted usb processes
            '26190899-1602-49e8-8b27-eb1d0a1ce869' = 1   # office comm app children
            '33ddedf1-c6e0-47cb-833e-de6133960387' = 1   # reboot into safe mode
            'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb' = 1   # copied/impersonated system tools
            '56a863a9-875e-4185-98a7-b882c64b5ce5' = 1   # vulnerable signed drivers
            '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c' = 1   # adobe reader child processes
            'a8f5898e-1dc8-49a9-9878-85004b8a61e6' = 1   # webshell creation for browsers
            'e6db77e5-3df2-4cf1-b95a-636979351e5b' = 1   # WMI persistence
        }
        $current = Get-MpPreference -ErrorAction Stop
        $curIds = @($current.AttackSurfaceReductionRules_Ids)
        $curActs = @($current.AttackSurfaceReductionRules_Actions)
        $ids = @(); $acts = @(); $foundInvalid = @()
        for ($i = 0; $i -lt $curIds.Count; $i++) {
            $id = "$($curIds[$i])"
            if (-not $id) { continue }
            if ($invalid -contains $id) { $foundInvalid += $id; continue }
            if ($ids -contains $id) { continue }
            $ids += $id
            $acts += $(if ($i -lt $curActs.Count -and $null -ne $curActs[$i]) { [int]$curActs[$i] } else { 1 })
        }
        foreach ($id in $asr.Keys) {
            if ($ids -notcontains $id) { $ids += $id; $acts += [int]$asr[$id] }
        }
        Set-MpPreference -AttackSurfaceReductionRules_Ids $ids -AttackSurfaceReductionRules_Actions $acts -ErrorAction Stop
        if ($foundInvalid.Count -gt 0) {
            Add-Finding -Id 'DEF-ASR-INVALID' -Area 'Defender' -Status 'WARN' -Detail "removed unrecognized ASR GUID(s): $($foundInvalid -join ', ')" `
                -Hint 'These GUIDs are not documented Defender ASR rules. They are reported here and removed from enforcement; keep the rest of the existing policy.'
        }
        $pref = Get-MpPreference -ErrorAction Stop
        $npNow = $pref.EnableNetworkProtection
        $np = if ($npNow -eq 1 -or $Aggressive) { 'Enabled' } else { 'AuditMode' }
        $cfaNow = $pref.EnableControlledFolderAccess
        $cfa = if ($cfaNow -eq 1 -or $Aggressive) { 'Enabled' } else { 'AuditMode' }
        Set-MpPreference -EnableNetworkProtection $np -EnableControlledFolderAccess $cfa -ErrorAction Stop
    }

    try {
        $pref = Get-MpPreference -ErrorAction Stop
        $asrIds  = @($pref.AttackSurfaceReductionRules_Ids | Where-Object { $_ })
        $asrActs = @($pref.AttackSurfaceReductionRules_Actions | Where-Object { $null -ne $_ })
        $asrOn = ($asrIds.Count -gt 0) -and (@($asrActs | Where-Object { $_ -eq 1 }).Count -gt 0)
        Add-Finding -Id 'DEF-ASR' -Area 'Defender' -Status $(if ($asrOn) {'PASS'} else {'WARN'}) `
            -Detail "ASR rules = $($asrIds.Count), block actions = $(@($asrActs | Where-Object { $_ -eq 1 }).Count)" `
            -Hint $(if ($asrOn) {''} else {'ASR policies can be blocked by tamper protection or an older platform. Re-check after reboot.'})
        $np = $pref.EnableNetworkProtection
        $npStatus = if ($np -eq 1) {'PASS'} elseif ($np -eq 2) {'WARN'} else {'WARN'}
        Add-Finding -Id 'DEF-NP' -Area 'Defender' -Status $npStatus `
            -Detail "EnableNetworkProtection = $np$(if ($np -eq 2) {' (audit only, not blocking)'})" `
            -Hint $(if ($np -eq 1) {''} else {'Set-MpPreference -EnableNetworkProtection Enabled. Audit mode records but does not block.'})
        $cfa = $pref.EnableControlledFolderAccess
        $cfaStatus = if ($cfa -eq 1) {'PASS'} elseif ($cfa -eq 2) {'WARN'} else {'WARN'}
        Add-Finding -Id 'DEF-CFA' -Area 'Defender' -Status $cfaStatus `
            -Detail "EnableControlledFolderAccess = $cfa$(if ($cfa -eq 2) {' (audit only, not blocking)'})" `
            -Hint $(if ($cfa -eq 1) {''} else {'Set-MpPreference -EnableControlledFolderAccess Enabled unless the README requires audit mode. Controlled folder access is unavailable on some builds or with a third-party AV; not every image scores it.'})
    } catch {}

    # exclusions are where "disabled AV" hides on CP images
    $script:DefenderExclusions = @()
    Invoke-CP -ReadOnly 'defender exclusion inventory' {
        $pref = Get-MpPreference -ErrorAction Stop
        $rows = @()
        foreach ($x in @($pref.ExclusionPath))      { if ($x) { $rows += [pscustomobject]@{Type='Path';Value=$x} } }
        foreach ($x in @($pref.ExclusionProcess))   { if ($x) { $rows += [pscustomobject]@{Type='Process';Value=$x} } }
        foreach ($x in @($pref.ExclusionExtension)) { if ($x) { $rows += [pscustomobject]@{Type='Extension';Value=$x} } }
        $rows | Export-Csv (Join-Path $script:EvDir 'defender-exclusions.csv') -NoTypeInformation
        $script:DefenderExclusions = @($rows)
        if ($rows.Count -gt 0) {
            Add-Finding -Id 'DEF-EXCL' -Area 'Defender' -Status 'WARN' -Detail "$($rows.Count) Defender exclusion(s) inventoried" `
                -Hint 'An exclusion covering C:\ or *.exe is "AV turned off" with extra steps. Remove it unless the README justifies it: Remove-MpPreference -ExclusionPath <path>'
        } else {
            Add-Finding -Id 'DEF-EXCL' -Area 'Defender' -Status 'PASS' -Detail 'no Defender exclusions'
        }
    }
    if ($script:DefenderExclusions.Count -gt 0 -and -not ($Paranoid -or $script:Dry)) {
        Write-Host ''
        $c = Read-Host '  remove ALL Defender exclusions? (y/N)'
        if ($c -match '^[Yy]') {
            $rows = @($script:DefenderExclusions)
            Invoke-CP 'remove Defender exclusions' {
                foreach ($r in $rows) {
                    if ($r.Type -eq 'Path')      { Remove-MpPreference -ExclusionPath      $r.Value -ErrorAction SilentlyContinue }
                    if ($r.Type -eq 'Process')   { Remove-MpPreference -ExclusionProcess   $r.Value -ErrorAction SilentlyContinue }
                    if ($r.Type -eq 'Extension') { Remove-MpPreference -ExclusionExtension $r.Value -ErrorAction SilentlyContinue }
                }
            } | Out-Null
        }
    }

    Invoke-CP 'signature update attempt' {
        Update-MpSignature -ErrorAction Stop
        Add-Finding -Id 'DEF-SIG' -Area 'Defender' -Status 'PASS' -Detail 'signatures updated'
    }
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        Add-Finding -Id 'DEF-AV' -Area 'Defender' -Status $(if ($mp.AntivirusEnabled) {'PASS'} else {'FAIL'}) `
            -Detail "AntivirusEnabled = $($mp.AntivirusEnabled)"
        Add-Finding -Id 'DEF-RT' -Area 'Defender' -Status $(if ($mp.RealTimeProtectionEnabled) {'PASS'} else {'FAIL'}) `
            -Detail "RealTimeProtection = $($mp.RealTimeProtectionEnabled)" `
            -Hint $(if ($mp.RealTimeProtectionEnabled) {''} else {'Tamper protection can block the change. Reboot and re-check, or fix via Windows Security UI.'})
    } catch {}

    # export history BEFORE the scan so a detection cannot rotate the answer away
    Invoke-CP -ReadOnly 'defender threat history' {
        $t = @(Get-MpThreatDetection -ErrorAction Stop)
        $t | Export-Csv (Join-Path $script:EvDir 'defender-threats.csv') -NoTypeInformation
        if ($t.Count -gt 0) {
            Add-Finding -Id 'DEF-THREAT' -Area 'Defender' -Status 'FAIL' -Detail "$($t.Count) threat detection(s) in history" `
                -Hint 'Get-MpThreat | Format-List -- record threat name, resource path, detection time. This is very often a forensic answer.'
        } else {
            Add-Finding -Id 'DEF-THREAT' -Area 'Defender' -Status 'PASS' -Detail 'no recorded threats'
        }
    }
    Invoke-CP 'defender quick scan' {
        Start-MpScan -ScanType QuickScan -ErrorAction Stop
        Add-Finding -Id 'DEF-SCAN' -Area 'Defender' -Status 'PASS' -Detail 'quick scan completed'
    } | Out-Null

    Invoke-CP 'windows update service re-enabled' {
        [void](Set-CPStartType -Name 'wuauserv' -Type 'Automatic')
        Start-Service wuauserv -ErrorAction SilentlyContinue
        [void](Set-CPStartType -Name 'BITS' -Type 'Automatic')
        Start-Service BITS -ErrorAction SilentlyContinue
        $st = Get-CPStartType 'wuauserv'
        if ($st -eq 'Unknown') {
            Add-Finding -Id 'WU-SVC' -Area 'Updates' -Status 'WARN' -Detail 'could not query the wuauserv start type' `
                -Hint 'Run: Get-Service wuauserv. Windows Update must be available for missing patches and signature updates.'
        } else {
            Add-Finding -Id 'WU-SVC' -Area 'Updates' -Status $(if ($st -ne 'Disabled') {'PASS'} else {'FAIL'}) -Detail "wuauserv = $st"
        }
    }

    Invoke-CP 'event log sizing + retention' {
        $target = 134217728
        $summary = @()
        $logBad = @()
        foreach ($l in @('Security','System','Application')) {
            $li = Get-WinEvent -ListLog $l -ErrorAction Stop
            if (-not $li) { throw "event log not found: $l" }
            if ([int64]$li.MaximumSizeInBytes -lt $target) {
                Invoke-CPNative wevtutil.exe @('sl', $l, ('/ms:' + $target)) | Out-Null
            }
            if ($li.LogMode -eq 'Circular') {
                Invoke-CPNative wevtutil.exe @('sl', $l, '/retention:true') | Out-Null
            }
            $now = Get-WinEvent -ListLog $l -ErrorAction Stop
            if ([int64]$now.MaximumSizeInBytes -lt $target) { throw "$l size postcondition failed" }
            if ($now.LogMode -eq 'Circular') { $logBad += "$l still circular" }
            $summary += "$l=$([math]::Round($now.MaximumSizeInBytes / 1MB))MB/$($now.LogMode)"
        }
        if ($logBad.Count -eq 0) {
            Add-Finding -Id 'LOG-SIZE' -Area 'Logging' -Status 'PASS' -Detail ("event logs >= 128 MB with retention: " + ($summary -join ', '))
        } else {
            Add-Finding -Id 'LOG-SIZE' -Area 'Logging' -Status 'WARN' -Detail ("event log sizing partly applied: " + ($logBad -join '; ')) `
                -Hint 'Check wevtutil sl <log> /rt:true and the log size in Event Viewer; policy may override retention.'
        }
    }

    Invoke-CP 'advanced audit policy (auditpol)' {
        # secedit sets the legacy flags; auditpol gives the subcategories the
        # scoring engine actually reads.
        $auditFail = @()
        foreach ($cat in @('System','Logon/Logoff','Object Access','Privilege Use','Detailed Tracking',
                           'Policy Change','Account Management','DS Access','Account Logon')) {
            [void](& auditpol /set /category:"$cat" /success:enable /failure:enable 2>&1)
            if ($LASTEXITCODE -ne 0) { $auditFail += "category:$cat" }
        }
        foreach ($sub in @('Process Creation','Logon','Special Logon','Other Logon/Logoff Events',
                           'Account Lockout','User Account Management','Security Group Management',
                           'Audit Policy Change','Sensitive Privilege Use','Removable Storage',
                           'File Share','Credential Validation','Other Account Logon Events')) {
            [void](& auditpol /set /subcategory:"$sub" /success:enable /failure:enable 2>&1)
            if ($LASTEXITCODE -ne 0) { $auditFail += "subcategory:$sub" }
        }
        # include the command line in 4688 process-creation events. gold for forensics.
        Set-CPReg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' `
            'ProcessCreationIncludeCmdLine_Enabled' 1 -Id 'AUD-CMDLINE' -Area 'Audit' | Out-Null
        $null = & auditpol /get /category:* 2>&1 | Set-Content (Join-Path $script:EvDir '81-auditpol.txt')
        if ($auditFail.Count -gt 0) {
            Add-Finding -Id 'AUD-ADV' -Area 'Audit' -Status 'WARN' -Detail ("auditpol rejected: " + ($auditFail -join ', ')) `
                -Hint 'Some categories/subcategories are unavailable on this SKU or localized. Verify with auditpol /get /category:* and set the missing names manually.'
        } else {
            Add-Finding -Id 'AUD-ADV' -Area 'Audit' -Status 'PASS' -Detail 'audit subcategories on, process command line logging on'
        }
    }

    # resource SACLs are separate from category audit policy. they are scored
    # on server images and cost nothing on a workstation.
    Invoke-CP 'resource SACLs (file/key)' {
        $prod = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).ProductType
        $who  = if ($prod -eq 2) { 'Domain Admins' } else { 'Administrator' }
        $null = & auditpol /resourceSACL /set /type:File "/user:$who" /success /failure /access:FW 2>&1
        $fileRc = $LASTEXITCODE
        $null = & auditpol /resourceSACL /set /type:Key  "/user:$who" /success /failure /access:FW 2>&1
        $keyRc = $LASTEXITCODE
        if ($fileRc -eq 0 -and $keyRc -eq 0) {
            Add-Finding -Id 'AUD-SACL' -Area 'Audit' -Status 'PASS' -Detail "resource SACLs set for $who (file + registry key)"
        } elseif ($fileRc -eq 0 -or $keyRc -eq 0) {
            Add-Finding -Id 'AUD-SACL' -Area 'Audit' -Status 'WARN' -Detail "resource SACL partial: file rc=$fileRc, key rc=$keyRc" `
                -Hint 'Check auditpol /resourceSACL /get /type:File and /type:Key. One object type may be unavailable on this SKU.'
        } else {
            throw 'auditpol /resourceSACL failed for File and Key'
        }
    } | Out-Null
}

# ------------------------------------------------------------------------------
# installed server apps: detect, harden config, NEVER touch their data
# ------------------------------------------------------------------------------
function Invoke-Apps {
    Write-Banner 'INSTALLED SERVICES / APPS'
    if (-not (Enter-CPPhase 'apps' -Mutating)) { return }

    # ---- legacy optional features ----------------------------------------
    $telnetOn = @()
    $telnetUnknown = @()
    foreach ($feat in @('TelnetClient','TelnetServer')) {
        try {
            $f = Get-WindowsOptionalFeature -Online -FeatureName $feat -ErrorAction Stop
            if ($f.State -eq 'Enabled') { $telnetOn += $feat }
        } catch { $telnetUnknown += $feat }
    }
    if ($telnetOn.Count -eq 0 -and $telnetUnknown.Count -eq 0) {
        Add-Finding -Id 'APP-TELNET' -Area 'Apps' -Status 'PASS' -Detail 'Telnet optional features are not enabled'
    } elseif ($telnetOn.Count -eq 0) {
        Add-Finding -Id 'APP-TELNET' -Area 'Apps' -Status 'WARN' -Detail ("could not verify Telnet optional features: " + ($telnetUnknown -join ', ')) `
            -Hint 'Run Get-WindowsOptionalFeature -Online -FeatureName TelnetClient,TelnetServer manually. Do not assume they are disabled.'
    } elseif ($Aggressive -and (Confirm-CP ("AGGRESSIVE: remove optional features " + ($telnetOn -join ', ') + "?"))) {
        foreach ($feat in $telnetOn) {
            $null = Invoke-CP ("remove optional feature " + $feat) {
                Disable-WindowsOptionalFeature -Online -FeatureName $feat -NoRestart -ErrorAction Stop | Out-Null
            }
        }
        $telnetLeft = @()
        foreach ($feat in $telnetOn) {
            try { if ((Get-WindowsOptionalFeature -Online -FeatureName $feat -ErrorAction Stop).State -eq 'Enabled') { $telnetLeft += $feat } }
            catch { $telnetLeft += $feat }
        }
        if ($telnetLeft.Count -eq 0) {
            Add-Finding -Id 'APP-TELNET' -Area 'Apps' -Status 'PASS' -Detail ("removed optional features: " + ($telnetOn -join ', '))
        } else {
            Add-Finding -Id 'APP-TELNET' -Area 'Apps' -Status 'WARN' -Detail ("still enabled: " + ($telnetLeft -join ', ')) `
                -Hint 'A pending restart or component-store (DISM) failure can leave the feature enabled. Check the OPERATION finding.'
        }
    } else {
        Add-Finding -Id 'APP-TELNET' -Area 'Apps' -Status 'WARN' -Detail ("Telnet optional feature enabled: " + ($telnetOn -join ', ')) `
            -Hint 'Re-run with -Aggressive to remove TelnetClient/TelnetServer once the README confirms they are not required.'
    }

    # other legacy features that are almost never required on a scored image
    $legacyOn = @()
    $legacyUnknown = @()
    foreach ($feat in @('TFTP','TFTP-Client','SimpleTCP','MicrosoftWindowsPowerShellV2Root')) {
        try {
            $f = Get-WindowsOptionalFeature -Online -FeatureName $feat -ErrorAction Stop
            if ($f.State -eq 'Enabled') { $legacyOn += $feat }
        } catch { $legacyUnknown += $feat }
    }
    $legacyOn = @($legacyOn | Select-Object -Unique)
    $legacyUnknown = @($legacyUnknown | Select-Object -Unique)
    if ($legacyOn.Count -eq 0 -and $legacyUnknown.Count -eq 0) {
        Add-Finding -Id 'APP-LEGACY-FEAT' -Area 'Apps' -Status 'PASS' -Detail 'TFTP / SimpleTCP / PowerShell-v2 features are not enabled'
    } elseif ($legacyOn.Count -eq 0) {
        Add-Finding -Id 'APP-LEGACY-FEAT' -Area 'Apps' -Status 'WARN' -Detail ("could not verify legacy optional features: " + ($legacyUnknown -join ', ')) `
            -Hint 'Query each feature manually with Get-WindowsOptionalFeature. Feature names differ between Windows editions.'
    } elseif ($Aggressive -and (Confirm-CP ("AGGRESSIVE: remove optional features " + ($legacyOn -join ', ') + "?"))) {
        foreach ($feat in $legacyOn) {
            $null = Invoke-CP ("remove optional feature " + $feat) {
                Disable-WindowsOptionalFeature -Online -FeatureName $feat -NoRestart -ErrorAction Stop | Out-Null
            }
        }
        $legacyLeft = @()
        foreach ($feat in $legacyOn) {
            try { if ((Get-WindowsOptionalFeature -Online -FeatureName $feat -ErrorAction Stop).State -eq 'Enabled') { $legacyLeft += $feat } }
            catch { $legacyLeft += $feat }
        }
        if ($legacyLeft.Count -eq 0) {
            Add-Finding -Id 'APP-LEGACY-FEAT' -Area 'Apps' -Status 'PASS' -Detail ("removed optional features: " + ($legacyOn -join ', '))
        } else {
            Add-Finding -Id 'APP-LEGACY-FEAT' -Area 'Apps' -Status 'WARN' -Detail ("still enabled: " + ($legacyLeft -join ', ')) `
                -Hint 'A pending restart or component-store (DISM) failure can leave the feature enabled. Check the OPERATION finding.'
        }
    } else {
        Add-Finding -Id 'APP-LEGACY-FEAT' -Area 'Apps' -Status 'WARN' -Detail ("legacy optional feature enabled: " + ($legacyOn -join ', ')) `
            -Hint 'Re-run with -Aggressive to remove TFTP/SimpleTCP/PowerShell-v2 once the README confirms they are not required.'
    }

    # ---- IIS -------------------------------------------------------------
    $iisSvc = Get-CPService 'W3SVC'
    if ($iisSvc -or (Test-Path C:\inetpub)) {
        Write-CP 'IIS detected' 'head'
        $ah = "$env:windir\System32\inetsrv\config\applicationHost.config"
        Invoke-CP 'IIS hardening (appcmd)' {
            $appcmd = "$env:windir\System32\inetsrv\appcmd.exe"
            if (-not (Test-Path $appcmd)) { throw 'appcmd.exe not found' }
            $bak = $null
            if (Test-Path $ah) { $bak = Backup-CPFile $ah }
            $current = if (Test-Path $ah) { Get-Content $ah -Raw } else { '' }

            $cmds = [System.Collections.Generic.List[object]]::new()
            $iisUnfixed = @()
            $cmds.Add(@('set','config','/section:directoryBrowse','/enabled:false','/commit:apphost'))
            $cmds.Add(@('set','config','/section:httpErrors','/errorMode:Custom','/commit:apphost'))
            foreach ($ext in @('.config','.cs','.csproj','.vb','.vbproj','.user','.webinfo','.licx','.resx',
                               '.resources','.mdb','.vbs','.java','.old','.bak','.orig','.save','.sql',
                               '.asa','.asax','.ashx','.asmx','.axd','.master','.sitemap','.ldf','.mdf')) {
                $m = [regex]::Match($current, '<add\s+[^>]*\bfileExtension\s*=\s*["'']' + [regex]::Escape($ext) + '["''][^>]*>', 'IgnoreCase')
                if (-not $m.Success) {
                    $cmds.Add(@('set','config','-section:requestFiltering',("/+`"fileExtensions.[fileExtension='$ext',allowed='False']`""),'/commit:apphost'))
                } elseif ($m.Value -notmatch '\ballowed\s*=\s*["''](?i:false)["'']') {
                    $iisUnfixed += "extension:$ext"
                }
            }
            foreach ($v in @('TRACE','TRACK','DEBUG','PROPFIND','PUT','DELETE')) {
                $m = [regex]::Match($current, '<add\s+[^>]*\bverb\s*=\s*["'']' + [regex]::Escape($v) + '["''][^>]*>', 'IgnoreCase')
                if (-not $m.Success) {
                    $cmds.Add(@('set','config','-section:requestFiltering',("/+`"verbs.[verb='$v',allowed='False']`""),'/commit:apphost'))
                } elseif ($m.Value -notmatch '\ballowed\s*=\s*["''](?i:false)["'']') {
                    $iisUnfixed += "verb:$v"
                }
            }
            foreach ($seq in @('..','%','%252e','%c0%af','%255c')) {
                if (-not [regex]::IsMatch($current, 'sequence\s*=\s*["'']' + [regex]::Escape($seq) + '["'']', 'IgnoreCase')) {
                    $cmds.Add(@('set','config','-section:requestFiltering',("/+`"denyUrlSequences.[sequence='$seq']`""),'/commit:apphost'))
                }
            }
            $cmds.Add(@('set','config','-section:requestFiltering','/requestLimits.maxAllowedContentLength:30000000','/commit:apphost'))
            foreach ($h in @(@('X-Content-Type-Options','nosniff'), @('X-Frame-Options','SAMEORIGIN'))) {
                $m = [regex]::Match($current, '<add\s+[^>]*\bname\s*=\s*["'']' + [regex]::Escape($h[0]) + '["''][^>]*>', 'IgnoreCase')
                if (-not $m.Success) {
                    $cmds.Add(@('set','config','-section:system.webServer/httpProtocol',("/+`"customHeaders.[name='$($h[0])',value='$($h[1])']`""),'/commit:apphost'))
                } elseif ($m.Value -notmatch ('\bvalue\s*=\s*["'']' + [regex]::Escape($h[1]) + '["'']')) {
                    $iisUnfixed += "header:$($h[0])"
                }
            }

            $failed = @()
            foreach ($a in $cmds) {
                $out = (& $appcmd @a 2>&1 | Out-String)
                if ($LASTEXITCODE -ne 0 -or $out -match '(?im)^\s*ERROR') {
                    $failed += (($a | Select-Object -Skip 2) -join ' ')
                }
            }
            if ($failed.Count -gt 0) {
                if ($bak) { Copy-Item -LiteralPath $bak -Destination $ah -Force -ErrorAction SilentlyContinue }
                throw ("appcmd failed: " + ($failed -join '; '))
            }
            if ($iisUnfixed.Count -gt 0) {
                Add-Finding -Id 'APP-IIS' -Area 'Apps' -Status 'WARN' -Detail 'IIS hardening partly applied; existing entries still allow restrictions' `
                    -Hint 'Review the APP-IIS-ALLOW list. This script does not overwrite pre-existing allow entries.'
                Add-Finding -Id 'APP-IIS-ALLOW' -Area 'Apps' -Status 'WARN' -Detail ("existing entries still allow: " + ($iisUnfixed -join ', ')) `
                    -Hint 'These entries were already present and were not overwritten. In IIS Manager > Request Filtering, set the file extension/verb to Deny, or update the custom header value, then re-run.'
            } else {
                Add-Finding -Id 'APP-IIS' -Area 'Apps' -Status 'PASS' -Detail 'IIS: dir browse off, request filtering, verbs blocked, security headers'
            }
        }
        if (Test-Path $ah) {
            $c = Get-Content $ah -Raw -ErrorAction SilentlyContinue
            if ($c -match 'anonymousAuthentication enabled="true"') {
                Add-Finding -Id 'APP-IIS-ANON' -Area 'Apps' -Status 'WARN' -Detail 'IIS anonymous authentication is enabled' `
                    -Hint 'If the site is not meant to be public, disable anonymousAuthentication and enable windowsAuthentication.'
            }
            if ($c -match '<logFile[^>]*enabled="false"') {
                Add-Finding -Id 'APP-IIS-LOG' -Area 'Apps' -Status 'FAIL' -Detail 'IIS logging is disabled' `
                    -Hint 'Enable logging and add Cookie/User-Agent/Referer to logExtFileFlags. IIS log config is a frequent scored item.'
            } else {
                Add-Finding -Id 'APP-IIS-LOG' -Area 'Apps' -Status 'INFO' -Detail 'verify IIS logExtFileFlags include Cookies, User-Agent, Referer'
            }
        }
    }

    # ---- Apache (Windows builds) ------------------------------------------
    foreach ($ap in @('C:\Apache24','C:\Program Files\Apache Software Foundation','C:\xampp\apache','C:\wamp64\bin\apache')) {
        if (-not (Test-Path $ap)) { continue }
        Write-CP "Apache detected at $ap" 'head'
        $conf = Get-ChildItem $ap -Recurse -Filter 'httpd.conf' -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $conf) { continue }
        $apacheHardened = Invoke-CP ("harden httpd.conf: " + $conf.FullName) {
            $bak = Backup-CPFile $conf.FullName
            $c = Get-Content $conf.FullName -Raw
            $orig = $c
            $c = $c -replace '(?im)^\s*ServerTokens\s+.*$',   'ServerTokens Prod'
            $c = $c -replace '(?im)^\s*ServerSignature\s+.*$', 'ServerSignature Off'
            $c = $c -replace '(?im)^\s*TraceEnable\s+.*$',     'TraceEnable Off'

            $lines = $c -split "`r?`n"
            for ($i = 0; $i -lt $lines.Count; $i++) {
                if ($lines[$i] -match '^(\s*Options\s+)(.+)$') {
                    $prefix = $matches[1]
                    $opts = $matches[2].Trim()
                    $opts = [regex]::Replace($opts, '(?i)(^|\s)\+?Indexes(?=\s|$)', '$1').Trim()
                    if ($opts -notmatch '(?i)(^|\s)-Indexes(\s|$)') { $opts = ($opts + ' -Indexes').Trim() }
                    $lines[$i] = $prefix + $opts
                }
            }
            $c = $lines -join "`r`n"

            $extra = @()
            if ($c -notmatch '(?im)^\s*ServerTokens\s')   { $extra += 'ServerTokens Prod' }
            if ($c -notmatch '(?im)^\s*ServerSignature\s') { $extra += 'ServerSignature Off' }
            if ($c -notmatch '(?im)^\s*TraceEnable\s')     { $extra += 'TraceEnable Off' }
            if ($extra.Count -gt 0) { $c += "`r`n# hardening (cbptwindows)`r`n" + ($extra -join "`r`n") + "`r`n" }

            if ($c -ne $orig) { Set-Content -Path $conf.FullName -Value $c -Encoding ASCII -ErrorAction Stop }
            $httpd = Join-Path $ap 'bin\httpd.exe'
            if (Test-Path $httpd) {
                $testOut = (& $httpd -t -f $conf.FullName 2>&1 | Out-String)
                if ($LASTEXITCODE -ne 0) {
                    Copy-Item -LiteralPath $bak -Destination $conf.FullName -Force -ErrorAction SilentlyContinue
                    throw ("httpd -t rejected the config; restored backup: " + $testOut.Trim())
                }
            }
            Add-Finding -Id 'APP-APACHE' -Area 'Apps' -Status 'PASS' -Detail "httpd.conf hardened: $($conf.FullName)"
        }
        Add-Finding -Id 'APP-APACHE-DIRS' -Area 'Apps' -Status 'INFO' -Detail 'manual Apache checks required' `
            -Hint 'Look for "Options Indexes FollowSymLinks", "Require all granted" on a filesystem root, TLSv1/1.1 in SSLProtocol. Restart Apache after every change and confirm it still listens.'
        $apacheRestart = Invoke-CP 'restart apache' {
            $svc = @(Get-Service 'Apache2.4','Apache2.2','Apache' -ErrorAction SilentlyContinue | Select-Object -First 1)
            if ($svc) { Restart-Service $svc.Name -Force -ErrorAction Stop }
        }
        if ($apacheHardened -and -not $script:Dry -and -not $apacheRestart) {
            Add-Finding -Id 'APP-APACHE-RESTART' -Area 'Apps' -Status 'WARN' -Detail 'httpd.conf hardened but Apache service restart failed' `
                -Hint 'Check the Apache error log, then restart the service manually. The config change is on disk but may not be active.'
        }
    }

    # ---- MySQL / MariaDB ----------------------------------------------------
    $myRoots = @('C:\Program Files\MySQL','C:\ProgramData\MySQL','C:\xampp\mysql','C:\wamp64\bin\mysql')
    $myRoots += @(Get-ChildItem 'C:\Program Files' -Directory -Filter 'MariaDB*' -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
    $foundMy = $false
    foreach ($my in $myRoots) { if (Test-Path $my) { $foundMy = $true; Write-CP "MySQL/MariaDB detected at $my" 'head'; break } }
    if ($foundMy) {
        $ini = @(Get-ChildItem @('C:\ProgramData\MySQL','C:\Windows','C:\Program Files\MySQL','C:\xampp\mysql') -Filter 'my.ini' -Recurse -ErrorAction SilentlyContinue) | Select-Object -First 1
        if ($ini) {
            Invoke-CP ("harden my.ini: " + $ini.FullName) {
                $null = Backup-CPFile $ini.FullName
                $lines = @(Get-Content $ini.FullName)
                $start = -1
                $end = $lines.Count
                for ($i = 0; $i -lt $lines.Count; $i++) {
                    if ($lines[$i] -match '^\s*\[\s*mysqld\s*\]\s*$') { $start = $i; continue }
                    if ($start -ge 0 -and $lines[$i] -match '^\s*\[') { $end = $i; break }
                }

                $hasBind = $false
                $hasSkipNetworking = $false
                $hasLocalInfile = $false
                $hasSymlink = $false
                if ($start -ge 0) {
                    for ($i = $start + 1; $i -lt $end; $i++) {
                        $line = $lines[$i]
                        if ($line -match '^\s*bind-address\s*=') {
                            $lines[$i] = 'bind-address=127.0.0.1'; $hasBind = $true
                        } elseif ($line -match '^\s*skip-networking\b\s*(=\s*(\S+))?') {
                            $val = $matches[2]
                            if (-not $val -or $val -notmatch '^(?i:0|false|off)$') { $hasSkipNetworking = $true }
                        } elseif ($line -match '^\s*local-infile\s*=') {
                            $lines[$i] = 'local-infile=0'; $hasLocalInfile = $true
                        } elseif ($line -match '^\s*skip-symbolic-links\s*(=\s*(\S+))?') {
                            $val = $matches[2]
                            if (-not $val -or $val -notmatch '^(?i:0|false|off)$') {
                                $hasSymlink = $true
                            } else {
                                $lines[$i] = 'skip-symbolic-links=1'; $hasSymlink = $true
                            }
                        } elseif ($line -match '^\s*symbolic-links\s*=') {
                            $lines[$i] = 'symbolic-links=0'; $hasSymlink = $true
                        }
                    }
                }

                $add = @()
                if (-not $hasBind -and -not $hasSkipNetworking) { $add += 'bind-address=127.0.0.1' }
                if (-not $hasLocalInfile) { $add += 'local-infile=0' }
                if (-not $hasSymlink) { $add += 'skip-symbolic-links=1' }
                if ($start -lt 0) {
                    $lines += '[mysqld]'
                    $end = $lines.Count
                }
                if ($add.Count -gt 0) {
                    $list = [System.Collections.Generic.List[string]]::new()
                    $list.AddRange([string[]]$lines)
                    $list.Insert($end, '# hardening (cbptwindows)')
                    $list.InsertRange($end + 1, [string[]]$add)
                    $lines = $list.ToArray()
                }
                $new = $lines -join "`r`n"
                $oldRaw = Get-Content $ini.FullName -Raw
                if ($new -ne $oldRaw) {
                    Set-Content -LiteralPath $ini.FullName -Value $new -Encoding ASCII -ErrorAction Stop
                }
                Add-Finding -Id 'APP-MYSQL' -Area 'Apps' -Status 'PASS' `
                    -Detail 'my.ini: [mysqld] binds to loopback (unless networking is disabled), local-infile off, symbolic links off'
            }
        } else {
            Add-Finding -Id 'APP-MYSQL' -Area 'Apps' -Status 'WARN' -Detail 'MySQL present but my.ini not found' `
                -Hint 'Search under ProgramData and the install dir for my.ini / my.cnf. Also check the service binPath for --defaults-file.'
        }
        Add-Finding -Id 'APP-MYSQL-SQL' -Area 'Apps' -Status 'INFO' -Detail 'manual MySQL work required' `
            -Hint "mysql -u root -p -e ""SELECT user,host,plugin FROM mysql.user;""  then: delete anonymous ('') users, DROP USER 'root'@'%', DROP DATABASE test, FLUSH PRIVILEGES. Or run mysql_secure_installation."
    }

    # ---- MSSQL --------------------------------------------------------------
    if (@(Get-Service 'MSSQL*' -ErrorAction SilentlyContinue).Count -gt 0) {
        Write-CP 'SQL Server detected' 'head'
        Invoke-CP 'SQL Browser disabled' {
            $b = Get-CPService 'SQLBrowser'
            if ($b) {
                Stop-Service SQLBrowser -Force -ErrorAction SilentlyContinue
                if (-not (Set-CPStartType -Name 'SQLBrowser' -Type 'Disabled')) { throw 'could not set SQLBrowser start type' }
                for ($i = 0; $i -lt 10; $i++) {
                    $b = Get-CPService 'SQLBrowser'
                    if (-not $b -or $b.Status -eq 'Stopped') { break }
                    Start-Sleep -Milliseconds 500
                }
                if ($b -and $b.Status -ne 'Stopped') { throw "SQL Browser is still $($b.Status)" }
            }
        } | Out-Null
        $b = Get-CPService 'SQLBrowser'
        if ($script:Dry) {
            if ($b) { Add-Finding -Id 'APP-MSSQL-BROWSER' -Area 'Apps' -Status 'INFO' -Detail 'SQL Browser would be disabled (dry-run)' }
        } elseif (-not $b) {
            Add-Finding -Id 'APP-MSSQL-BROWSER' -Area 'Apps' -Status 'PASS' -Detail 'SQL Browser service not installed'
        } elseif ((Get-CPStartType 'SQLBrowser') -eq 'Disabled' -and $b.Status -eq 'Stopped') {
            Add-Finding -Id 'APP-MSSQL-BROWSER' -Area 'Apps' -Status 'PASS' -Detail 'SQL Browser disabled and stopped'
        } else {
            Add-Finding -Id 'APP-MSSQL-BROWSER' -Area 'Apps' -Status 'WARN' -Detail 'SQL Browser still enabled' `
                -Hint 'Stop-Service SQLBrowser; Set-Service SQLBrowser -StartupType Disabled.'
        }
        Add-Finding -Id 'APP-MSSQL' -Area 'Apps' -Status 'INFO' -Detail 'SQL Server present, manual checks required' `
            -Hint 'Disable/rename sa + strong password; Windows-only auth unless the README requires mixed mode; remove BUILTIN\Users login; confirm SQL Browser is off.'
    }
}

# ------------------------------------------------------------------------------
# file inventory (media / password files / user executables). NOTHING deleted.
# ------------------------------------------------------------------------------
function Invoke-Files {
    Write-Banner 'FILE INVENTORY (no deletes)'
    if (-not (Enter-CPPhase 'files')) { return }

    $media = '*.mp3','*.mp4','*.m4a','*.avi','*.mkv','*.mov','*.wmv','*.flac','*.wav','*.ogg','*.torrent','*.pcap'
    $rows = @()
    foreach ($p in (Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue)) {
        if ($p.Name -in @('Default','Default User','All Users','Public')) { continue }
        $rows += @(Get-ChildItem $p.FullName -Recurse -File -Include $media -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -notmatch '\\AppData\\' } |
            Select-Object FullName,Length,LastWriteTime)
    }
    $rows | Export-Csv (Join-Path $script:EvDir 'media-files.csv') -NoTypeInformation
    if ($rows.Count -gt 0) {
        Add-Finding -Id 'FILES-MEDIA' -Area 'Files' -Status 'WARN' -Detail "$($rows.Count) media/prohibited-type file(s) inventoried" `
            -Hint 'Delete ONLY what the README calls prohibited (usually a media/p2p policy). Games and movies in user folders are usually points.'
    } else {
        Add-Finding -Id 'FILES-MEDIA' -Area 'Files' -Status 'PASS' -Detail 'no media files in user profiles'
    }

    $exe = @()
    foreach ($p in (Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue)) {
        foreach ($sub in @('Desktop','Downloads','Documents')) {
            $d = Join-Path $p.FullName $sub
            if (-not (Test-Path $d)) { continue }
            $exe += @(Get-ChildItem $d -Recurse -File -Include *.exe,*.msi,*.bat,*.cmd,*.ps1,*.vbs,*.scr -ErrorAction SilentlyContinue |
                Select-Object FullName,Length,LastWriteTime)
        }
    }
    $exe | Export-Csv (Join-Path $script:EvDir 'user-executables.csv') -NoTypeInformation
    if ($exe.Count -gt 0) {
        Add-Finding -Id 'FILES-EXE' -Area 'Files' -Status 'WARN' -Detail "$($exe.Count) executable(s)/script(s) in user folders" `
            -Hint 'Check each against the README and the forensic questions before deleting. Unexplained exes are usually malware.'
    } else {
        Add-Finding -Id 'FILES-EXE' -Area 'Files' -Status 'PASS' -Detail 'no executables in user folders'
    }

    $docs = @()
    foreach ($p in (Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue)) {
        $docs += @(Get-ChildItem $p.FullName -Recurse -File -Include *.txt,*.csv,*.xlsx,*.docx -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '(?i)pass|cred|secret|hack|crack|keylog|login' -and $_.FullName -notmatch '\\AppData\\' } |
            Select-Object FullName,Length)
    }
    $docs | Export-Csv (Join-Path $script:EvDir 'suspect-documents.csv') -NoTypeInformation
    if ($docs.Count -gt 0) {
        Add-Finding -Id 'FILES-DOCS' -Area 'Files' -Status 'WARN' -Detail "$($docs.Count) password/credential-named document(s)" `
            -Hint 'Password lists are usually a scored policy violation. Record the path in the report; deleting business data loses points.'
    } else {
        Add-Finding -Id 'FILES-DOCS' -Area 'Files' -Status 'PASS' -Detail 'no password-named documents in user profiles'
    }
    Write-CP "full inventory -> $script:EvDir" 'ok'
}
# ------------------------------------------------------------------------------
# verify / scorecard
# ------------------------------------------------------------------------------
function Invoke-Verify {
    Write-Banner 'VERIFY'
    if (-not (Enter-CPPhase 'verify')) { return }

    # ---- secedit re-export -------------------------------------------------
    Invoke-CP -ReadOnly 'secedit re-export + policy checks' {
        $tmp = Get-SeceditInf
        $raw = @(Get-Content $tmp)
        $pol = @{}
        foreach ($line in $raw) {
            if ($line -match '^\s*([A-Za-z0-9_]+)\s*=\s*(.+?)\s*$') { $pol[$Matches[1]] = $Matches[2] }
        }
        function Get-PolNum { param([string]$k) $n = 0; if ($pol.ContainsKey($k) -and [int]::TryParse($pol[$k], [ref]$n)) { return $n } return -1 }

        # k = key, min/max = acceptable range (-1 = unconstrained)
        $cmp = @(
            @{ k='MinimumPasswordLength';  min=14; max=-1;  want='>=14' }
            @{ k='PasswordComplexity';     min=1;  max=1;   want='1' }
            @{ k='PasswordHistorySize';    min=10; max=-1;  want='>=10' }
            @{ k='MinimumPasswordAge';     min=1;  max=-1;  want='>=1' }
            @{ k='MaximumPasswordAge';     min=1;  max=90;  want='1..90' }
            @{ k='LockoutBadCount';        min=1;  max=5;   want='1..5' }
            @{ k='LockoutDuration';        min=15; max=-1;  want='>=15' }
            @{ k='ResetLockoutCount';      min=15; max=-1;  want='>=15' }
            @{ k='ClearTextPassword';      min=0;  max=0;   want='0' }
            @{ k='LSAAnonymousNameLookup'; min=0;  max=0;   want='0' }
            @{ k='EnableGuestAccount';     min=0;  max=0;   want='0' }
        )
        foreach ($x in $cmp) {
            $v = Get-PolNum $x.k
            if ($v -lt 0) {
                Add-Finding -Id "VER-$($x.k)" -Area 'Verify' -Status 'FAIL' -Detail "$($x.k) is not set (want $($x.want))" `
                    -Hint 'Re-run the users section, or set it in secpol.msc > Account Policies.'
                continue
            }
            $good = ($v -ge $x.min) -and ($x.max -lt 0 -or $v -le $x.max)
            Add-Finding -Id "VER-$($x.k)" -Area 'Verify' -Status $(if ($good) {'PASS'} else {'FAIL'}) -Detail "$($x.k) = $v (want $($x.want))" `
                -Hint $(if ($good) {''} else {'Re-run the users section, or set it in secpol.msc > Account Policies.'})
        }

        foreach ($a in @('AuditLogonEvents','AuditAccountManage','AuditObjectAccess','AuditPolicyChange',
                         'AuditPrivilegeUse','AuditSystemEvents','AuditAccountLogon','AuditProcessTracking','AuditDSAccess')) {
            $v = Get-PolNum $a
            Add-Finding -Id "VER-$a" -Area 'Verify' -Status $(if ($v -eq 3) {'PASS'} else {'FAIL'}) `
                -Detail "$a = $(if($v -ge 0){$v}else{'<not set>'}) (want 3 = success+failure)"
        }
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    }

    # ---- registry spot checks -------------------------------------------------
    $regChecks = @(
        @{p='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; n='EnableLUA'; want='1'; id='VER-UAC'},
        @{p='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; n='ConsentPromptBehaviorAdmin'; want='2'; id='VER-UAC-Consent'},
        @{p='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; n='PromptOnSecureDesktop'; want='1'; id='VER-UAC-SecDesk'},
        @{p='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; n='RestrictAnonymous'; want='1'; id='VER-RestrictAnon'},
        @{p='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; n='RestrictAnonymousSAM'; want='1'; id='VER-RestrictAnonSAM'},
        @{p='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; n='NoLMHash'; want='1'; id='VER-NoLMHash'},
        @{p='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; n='LMCompatibilityLevel'; want='5'; id='VER-LMCompat'},
        @{p='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; n='DisableDomainCreds'; want='1'; id='VER-DisableDomainCreds'},
        @{p='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; n='LimitBlankPasswordUse'; want='1'; id='VER-BlankPw'},
        @{p='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; n='RunAsPPL'; want='1'; id='VER-RunAsPPL'},
        @{p='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\WDigest'; n='UseLogonCredential'; want='0'; id='VER-WDigest'},
        @{p='HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; n='RequireSecuritySignature'; want='1'; id='VER-SMBSign'},
        @{p='HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'; n='RequireSecuritySignature'; want='1'; id='VER-SMBSignC'},
        @{p='HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'; n='DisableIPSourceRouting'; want='2'; id='VER-IPSrcRoute'},
        @{p='HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'; n='EnableICMPRedirect'; want='0'; id='VER-ICMPRedirect'},
        @{p='HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'; n='SynAttackProtect'; want='1'; id='VER-SynProtect'},
        @{p='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; n='Hidden'; want='1'; id='VER-ShowHidden'},
        @{p='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; n='HideFileExt'; want='0'; id='VER-ShowExt'},
        @{p='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; n='NoDriveTypeAutoRun'; want='255'; id='VER-Autorun'},
        @{p='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; n='EnableScriptBlockLogging'; want='1'; id='VER-PSLog'},
        @{p='HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'; n='UserAuthentication'; want='1'; id='VER-NLA'},
        @{p='HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'; n='EnablePlainTextPassword'; want='0'; id='VER-PlainTextPw'},
        @{p='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments'; n='ScanWithAntiVirus'; want='3'; id='VER-AttachScan'},
        @{p='HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'; n='CrashDumpEnabled'; want='0'; id='VER-CrashDump'},
        @{p='HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance'; n='fAllowToGetHelp'; want='0'; id='VER-RA'},
        @{p='HKCU:\Software\Policies\Microsoft\office\16.0\word\security'; n='vbawarnings'; want='4'; id='VER-OfficeMacro'}
    )
    foreach ($r in $regChecks) {
        $v = Get-CPReg -Path $r.p -Name $r.n
        if ($null -eq $v) {
            Add-Finding -Id $r.id -Area 'Verify' -Status 'WARN' -Detail "$($r.n) not set" -Hint "Missing under $($r.p). Re-run the registry section."
        } else {
            $good = ("$v" -eq $r.want)
            Add-Finding -Id $r.id -Area 'Verify' -Status $(if ($good) {'PASS'} else {'FAIL'}) -Detail "$($r.n) = $v (want $($r.want))"
        }
    }

    # Office policy is user-specific; check the common macro-kill switch too.
    $officeAuto = Get-CPReg -Path 'HKCU:\Software\Policies\Microsoft\office\16.0\common\security' -Name 'automationsecurity'
    Add-Finding -Id 'VER-OfficeAuto' -Area 'Verify' -Status $(if ("$officeAuto" -eq '3') {'PASS'} else {'WARN'}) `
        -Detail "Office automationsecurity = $officeAuto (want 3)"

    # WinRM TrustedHosts must never be '*'. It grants credential forwarding to
    # any host and is a common "make remoting work" mistake on practice images.
    try {
        $th = (Get-Item WSMan:\localhost\Client\TrustedHosts -ErrorAction Stop).Value
        $thEntries = @("$th" -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        if ($thEntries -contains '*') {
            Add-Finding -Id 'VER-WSMAN' -Area 'Verify' -Status 'FAIL' -Detail "WinRM TrustedHosts contains wildcard: '$th'" `
                -Hint 'Clear it: Set-Item WSMan:\localhost\Client\TrustedHosts -Value "" -Force. Use explicit hostnames if remote management is required.'
        } else {
            Add-Finding -Id 'VER-WSMAN' -Area 'Verify' -Status 'PASS' -Detail "WinRM TrustedHosts = '$th'"
        }
    } catch {
        Add-Finding -Id 'VER-WSMAN' -Area 'Verify' -Status 'WARN' -Detail 'could not query WinRM TrustedHosts' `
            -Hint 'Run: Get-Item WSMan:\localhost\Client\TrustedHosts ; if WinRM is not used, confirm the service is stopped. Do not assume the list is empty.'
    }

    # A Microsoft.PowerShell session config that grants Everyone (WD) full
    # access is a backdoor. It is not something this script ever sets.
    try {
        $sd = (Get-PSSessionConfiguration -Name 'Microsoft.PowerShell' -ErrorAction Stop).SecurityDescriptorSddl
        if ("$sd" -match '\(A;;GA;;;WD\)') {
            Add-Finding -Id 'VER-PSSESSION' -Area 'Verify' -Status 'FAIL' -Detail 'PowerShell session config grants Everyone full access' `
                -Hint 'Reset it: Set-PSSessionConfiguration -Name Microsoft.PowerShell -SecurityDescriptorSddl <default SDDL>, or use Disable-PSRemoting if remoting is not required.'
        } else {
            Add-Finding -Id 'VER-PSSESSION' -Area 'Verify' -Status 'PASS' -Detail 'PowerShell session config does not grant Everyone'
        }
    } catch {
        Add-Finding -Id 'VER-PSSESSION' -Area 'Verify' -Status 'INFO' -Detail 'PowerShell session config not readable (remoting may be off)'
    }

    # Defender sandbox is an environment variable, not a registry value.
    $sb = [Environment]::GetEnvironmentVariable('MP_FORCE_USE_SANDBOX','Machine')
    Add-Finding -Id 'VER-DEF-SANDBOX' -Area 'Verify' -Status $(if ("$sb" -eq '1') {'PASS'} else {'WARN'}) `
        -Detail "MP_FORCE_USE_SANDBOX = $sb"

    # LOLBin egress rules
    if ($NoLolbinBlocks) {
        Add-Finding -Id 'VER-LOLBIN' -Area 'Verify' -Status 'SKIP' -Detail 'LOLBin outbound blocks disabled by flag'
    } else {
        try {
            $expected = @(Get-CPLolbinPaths)
            $rules = @(Get-NetFirewallRule -DisplayName 'CP Block outbound*' -ErrorAction SilentlyContinue)
            $good = @($rules | Where-Object {
                $_.Enabled -eq 'True' -and $_.Direction -eq 'Outbound' -and $_.Action -eq 'Block'
            })
            $goodNames = @($good | ForEach-Object { $_.Name })
            $missing = @($expected | Where-Object { $goodNames -notcontains $_.Name })
            if ($expected.Count -eq 0) {
                Add-Finding -Id 'VER-LOLBIN' -Area 'Verify' -Status 'PASS' -Detail 'no LOLBin executables found to block'
            } elseif ($missing.Count -eq 0) {
                Add-Finding -Id 'VER-LOLBIN' -Area 'Verify' -Status 'PASS' -Detail "all $($expected.Count) expected LOLBin outbound block rule(s) enabled"
            } else {
                Add-Finding -Id 'VER-LOLBIN' -Area 'Verify' -Status 'FAIL' -Detail "$($missing.Count) of $($expected.Count) LOLBin outbound block rule(s) missing or disabled" `
                    -Hint 'Re-run the network phase elevated. Review the FIREWALL section for per-rule errors.'
            }
        } catch {
            Add-Finding -Id 'VER-LOLBIN' -Area 'Verify' -Status 'WARN' -Detail 'could not query LOLBin firewall rules' `
                -Hint 'Confirm the Windows Firewall service is running, then re-run.'
        }
    }

    # autologon: an absent key is also a PASS, but a cached DefaultPassword is not
    $winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $al = Get-CPReg -Path $winlogon -Name 'AutoAdminLogon'
    $dp = Get-CPReg -Path $winlogon -Name 'DefaultPassword'
    $autoGood = ($null -eq $al -or "$al" -eq '0') -and ($null -eq $dp -or "$dp" -eq '')
    Add-Finding -Id 'VER-AutoLogon' -Area 'Verify' -Status $(if ($autoGood) {'PASS'} else {'FAIL'}) `
        -Detail "AutoAdminLogon=$al; DefaultPassword=$(if ($null -eq $dp) {'<absent>'} elseif ("$dp" -eq '') {'<empty>'} else {'<present>'})" `
        -Hint $(if ($autoGood) {''} else {'Remove the cached DefaultPassword value from Winlogon and set AutoAdminLogon=0.'})

    # ---- guest + hidden + RID500 ----------------------------------------------
    $g = @(Get-CPUsers) | Where-Object { $_.SID -match '-501$' } | Select-Object -First 1
    if ($g) { Add-Finding -Id 'VER-GUEST' -Area 'Verify' -Status $(if (-not $g.Enabled) {'PASS'} else {'FAIL'}) -Detail "guest enabled = $($g.Enabled)" }
    $allUsers = @(Get-CPUsers)
    $r5 = $allUsers | Where-Object { $_.SID -match '-500$' -and $_.Name -ne 'Administrator' } | Select-Object -First 1
    if ($r5) {
        Add-Finding -Id 'VER-RID500' -Area 'Verify' -Status 'INFO' -Detail "RID-500 account is renamed: $($r5.Name)" `
            -Hint 'A renamed RID-500 account is not proof of a clone. Compare verified SIDs and account history.'
    } else {
        Add-Finding -Id 'VER-RID500' -Area 'Verify' -Status 'PASS' -Detail 'RID-500 account has the default name'
    }
    $dupSid = @($allUsers | Where-Object { $_.SID } | Group-Object SID | Where-Object { $_.Count -gt 1 })
    if ($dupSid.Count -gt 0) {
        Add-Finding -Id 'VER-RID500-DUP' -Area 'Verify' -Status 'FAIL' -Detail ("duplicate local SIDs: " + (($dupSid | ForEach-Object { $_.Name }) -join ', ')) `
            -Hint 'Duplicate SIDs indicate account cloning. Investigate the account history before deleting anything.'
    }

    if ($DisableBuiltinAdmin) {
        $ba = @(Get-CPUsers | Where-Object { $_.SID -match '-500$' }) | Select-Object -First 1
        if ($ba) {
            Add-Finding -Id 'VER-BUILTIN-ADMIN' -Area 'Verify' -Status $(if (-not $ba.Enabled) {'PASS'} else {'FAIL'}) `
                -Detail "built-in Administrator enabled = $($ba.Enabled)"
        }
    }

    # ---- defender ------------------------------------------------------------
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        Add-Finding -Id 'VER-DEF-RT' -Area 'Verify' -Status $(if ($mp.RealTimeProtectionEnabled) {'PASS'} else {'FAIL'}) -Detail "RealTimeProtection = $($mp.RealTimeProtectionEnabled)"
        Add-Finding -Id 'VER-DEF-AV' -Area 'Verify' -Status $(if ($mp.AntivirusEnabled) {'PASS'} else {'FAIL'}) -Detail "AntivirusEnabled = $($mp.AntivirusEnabled)"
        $pref = Get-MpPreference -ErrorAction Stop
        Add-Finding -Id 'VER-DEF-PUA' -Area 'Verify' -Status $(if ($pref.PUAProtection -eq 1) {'PASS'} elseif ($pref.PUAProtection -eq 2) {'WARN'} else {'FAIL'}) -Detail "PUAProtection = $($pref.PUAProtection)"
        $asrIds = @($pref.AttackSurfaceReductionRules_Ids | Where-Object { $_ })
        $asrBlock = @($pref.AttackSurfaceReductionRules_Actions | Where-Object { $_ -eq 1 }).Count
        Add-Finding -Id 'VER-DEF-ASR' -Area 'Verify' -Status $(if ($asrBlock -ge 10) {'PASS'} else {'WARN'}) -Detail "ASR rules = $($asrIds.Count), block actions = $asrBlock" `
            -Hint $(if ($asrBlock -ge 10) {''} else {'Audit-mode ASR rules do not block. Set the IMPORTANT rules to Block in Windows Security or Intune.'})
    } catch {
        Add-Finding -Id 'VER-DEF-ERROR' -Area 'Verify' -Status 'WARN' -Detail 'Defender status could not be queried' `
            -Hint 'Check Get-MpComputerStatus. A third-party AV or a disabled Defender service can make these checks unavailable; do not assume the image is protected.'
    }

    # ---- services that should be off -------------------------------------------
    foreach ($n in @('RemoteRegistry','TlntSvr','Fax','SSDPSRV','upnphost','SharedAccess','RpcLocator','WMPNetworkSvc','Simptcp','RemoteAccess')) {
        $s = Get-CPService $n
        if ($s) {
            $st = Get-CPStartType $n
            $good = ($st -eq 'Disabled' -and $s.Status -ne 'Running')
            Add-Finding -Id "VER-SVC-$n" -Area 'Verify' -Status $(if ($good) {'PASS'} else {'FAIL'}) -Detail "$n = $($s.Status)/$st"
        }
    }

    # ---- SMBv1 -------------------------------------------------------------------
    try {
        $f = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
        Add-Finding -Id 'VER-SMBV1' -Area 'Verify' -Status $(if ($f.State -ne 'Enabled') {'PASS'} else {'FAIL'}) -Detail "SMB1Protocol = $($f.State)"
    } catch {
        Add-Finding -Id 'VER-SMBV1-ERROR' -Area 'Verify' -Status 'WARN' -Detail 'could not query the SMB1 feature state' `
            -Hint 'Run: Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol. Do not assume SMB1 is disabled.'
    }

    # ---- optional Telnet features ------------------------------------------------
    try {
        $telnetOn = @()
        $telnetUnknown = @()
        foreach ($feat in @('TelnetClient','TelnetServer')) {
            try {
                $f = Get-WindowsOptionalFeature -Online -FeatureName $feat -ErrorAction Stop
                if ($f.State -eq 'Enabled') { $telnetOn += $feat }
            } catch { $telnetUnknown += $feat }
        }
        if ($telnetOn.Count -gt 0) {
            Add-Finding -Id 'VER-TELNET' -Area 'Verify' -Status 'WARN' -Detail "enabled: $($telnetOn -join ', ')"
        } elseif ($telnetUnknown.Count -gt 0) {
            Add-Finding -Id 'VER-TELNET' -Area 'Verify' -Status 'WARN' -Detail "could not verify: $($telnetUnknown -join ', ')"
        } else {
            Add-Finding -Id 'VER-TELNET' -Area 'Verify' -Status 'PASS' -Detail 'Telnet optional features off'
        }
    } catch {
        Add-Finding -Id 'VER-TELNET-ERROR' -Area 'Verify' -Status 'WARN' -Detail 'could not query Telnet optional features' `
            -Hint 'Run: Get-WindowsOptionalFeature -Online -FeatureName TelnetClient,TelnetServer. Do not assume they are off.'
    }

    # ---- wuauserv ------------------------------------------------------------------
    $st = Get-CPStartType 'wuauserv'
    if ($st -eq 'Unknown') {
        Add-Finding -Id 'VER-WU' -Area 'Verify' -Status 'WARN' -Detail 'could not query the wuauserv start type' `
            -Hint 'Run: Get-Service wuauserv | Select-Object Name,Status,StartType. Windows Update must not be Disabled.'
    } else {
        Add-Finding -Id 'VER-WU' -Area 'Verify' -Status $(if ($st -ne 'Disabled') {'PASS'} else {'FAIL'}) -Detail "wuauserv = $st"
    }

    # ---- reboot needed? --------------------------------------------------------------
    $reboot = @()
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $reboot += 'CBS pending' }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $reboot += 'Windows Update required' }
    $pfr = Get-CPReg -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations'
    if ($null -ne $pfr -and @($pfr).Count -gt 0) { $reboot += 'pending file rename' }
    if ($reboot.Count -gt 0) {
        Add-Finding -Id 'VER-REBOOT' -Area 'Verify' -Status 'WARN' -Detail "reboot recommended ($($reboot -join '; '))" `
            -Hint 'Reboot BEFORE the final scoring pass -- but never with less than ~25 minutes on the clock. Some checks only read live state, others only read boot state.'
    } else {
        Add-Finding -Id 'VER-REBOOT' -Area 'Verify' -Status 'PASS' -Detail 'no reboot pending'
    }
}

function Export-Report {
    Write-Banner 'SCORECARD'
    New-Item -ItemType Directory -Path $script:EvDir -Force -ErrorAction SilentlyContinue | Out-Null
    $f = @($script:Findings)
    $pass = @($f | Where-Object { $_.Status -eq 'PASS' }).Count
    $fail = @($f | Where-Object { $_.Status -eq 'FAIL' }).Count
    $warn = @($f | Where-Object { $_.Status -eq 'WARN' }).Count
    $info = @($f | Where-Object { $_.Status -eq 'INFO' }).Count
    $skip = @($f | Where-Object { $_.Status -eq 'SKIP' }).Count
    $total = $pass + $fail + $warn
    $pct = 0
    if ($total -gt 0) { $pct = [math]::Round(100.0 * $pass / $total, 1) }

    Write-Host ''
    Write-Host ("  PASS {0,-4}  FAIL {1,-4}  WARN {2,-4}  INFO {3,-4}  SKIP {4}" -f $pass,$fail,$warn,$info,$skip) -ForegroundColor White
    Write-Host ("  automated coverage: {0}%   (this is NOT your score -- see the hints guide)" -f $pct) -ForegroundColor Cyan
    Write-Host ''

    if ($fail -gt 0) {
        Write-Host '  ---- FAIL (fix these first) ----' -ForegroundColor Red
        $f | Where-Object { $_.Status -eq 'FAIL' } | ForEach-Object {
            Write-Host ("   {0,-30} {1}" -f $_.Id, $_.Detail) -ForegroundColor Red
            if ($_.Hint) { Write-Host ("       hint: {0}" -f $_.Hint) -ForegroundColor DarkYellow }
        }
        Write-Host ''
    }
    if ($warn -gt 0) {
        Write-Host '  ---- WARN (decide with the README in hand) ----' -ForegroundColor Yellow
        $f | Where-Object { $_.Status -eq 'WARN' } | ForEach-Object {
            Write-Host ("   {0,-30} {1}" -f $_.Id, $_.Detail) -ForegroundColor Yellow
            if ($_.Hint) { Write-Host ("       hint: {0}" -f $_.Hint) -ForegroundColor DarkYellow }
        }
        Write-Host ''
    }
    if ($info -gt 0) {
        Write-Host '  ---- INFO (things this script refuses to do for you) ----' -ForegroundColor DarkGray
        $f | Where-Object { $_.Status -eq 'INFO' } | ForEach-Object {
            Write-Host ("   {0,-30} {1}" -f $_.Id, $_.Detail) -ForegroundColor DarkGray
            if ($_.Hint) { Write-Host ("       hint: {0}" -f $_.Hint) -ForegroundColor DarkCyan }
        }
        Write-Host ''
    }

    if ($script:Changed.Count -gt 0) {
        Write-Host "  ---- changes made this run: $($script:Changed.Count) ----" -ForegroundColor Magenta
        $script:Changed | Select-Object -First 50 | ForEach-Object {
            Write-Host ("   {0,-56} {1} -> {2}" -f $_.What, $_.Old, $_.New) -ForegroundColor DarkMagenta
        }
        if ($script:Changed.Count -gt 50) { Write-Host "   ... and $($script:Changed.Count - 50) more (see changes.csv)" -ForegroundColor DarkGray }
        $script:Changed | Export-Csv (Join-Path $script:EvDir 'changes.csv') -NoTypeInformation
    }

    $f | Export-Csv (Join-Path $script:EvDir 'findings.csv') -NoTypeInformation
    try { $f | ConvertTo-Json -Depth 3 | Set-Content (Join-Path $script:EvDir 'findings.json') } catch {}

    if (Test-Path $script:ReviewFile) {
        $rev = @(Get-Content $script:ReviewFile | Where-Object { $_ })
        if ($rev.Count -gt 0) {
            Write-Host "  ---- needs a human decision (needs-review.txt) ----" -ForegroundColor Yellow
            $rev | Select-Object -First 25 | ForEach-Object { Write-Host ("   {0}" -f $_) -ForegroundColor Yellow }
            if ($rev.Count -gt 25) { Write-Host "   ... and $($rev.Count - 25) more in needs-review.txt" -ForegroundColor DarkGray }
        }
    }

    Write-CP "findings -> $script:EvDir\findings.csv" 'ok'
    Write-CP "backup   -> $script:BkDir   (keep it until the round ends)" 'warn'
    Write-CP "log      -> $script:LogFile" 'ok'
}
# ------------------------------------------------------------------------------
# the point-scrounging guide. the most important function in the file.
# ------------------------------------------------------------------------------
function Show-Hints {
    Write-Banner 'HOW TO ACTUALLY MAX THE SCORE (WINDOWS)'
    $help = @'

 THE PART NOBODY TELLS YOU
 -------------------------
 A script gets you the boring 40-60%. Every team can automate that part too.
 The spread between the team that places and the team that does not is almost
 entirely in the manual work: reading the README, answering the forensic
 questions, and finding the backdoor that is actually on THIS image.

 ORDER OF OPERATIONS (a ~6 hour image)
 -------------------------------------
 0:00  README. do not skim it. write down on paper:
         - authorized users (names, groups, which must be admin)
         - critical services (these MUST keep running)
         - business documents / PII that must be preserved
         - every explicit task ("enable X", "remove Y", "change Z")
       README tasks + forensics are the cheapest points on the image.
 0:10  Forensic questions. answer them BEFORE hardening -- hardening rotates
       logs and overwrites the evidence they ask about. do NOT clear logs.
 0:30  .\cbptwindows.ps1 -Phase recon -Paranoid      (look, do not touch)
       read every WARN and FAIL. that IS your vulnerability list.
 0:45  fill in users.txt + admins.txt from the README.
 1:00  .\cbptwindows.ps1 -Phase users                (reconcile + policy)
 1:30  .\cbptwindows.ps1 -Phase registry
 1:45  .\cbptwindows.ps1 -Phase network  and  -Phase services
 2:00  manual backdoor hunt (commands below). screenshot everything.
 2:30  -Phase defender  and  -Phase apps. start Windows Update EARLY --
       it takes forever, do forensics while it runs.
 3:00  re-read the README. do the specific tasks it asked for, by hand.
 3:30  critical services: verify each one still answers. restart them.
       a dead critical service costs more than ten registry keys.
 4:00  share + NTFS permissions on anything holding PII. fix BOTH layers.
 4:30  -Phase apps / app hardening by hand: IIS, Apache, MySQL, FTP.
       after EVERY config edit: restart the service, confirm it listens.
 5:00  .\cbptwindows.ps1 -Phase verify. fix every FAIL. reboot if >25 min left.
 5:30  write the vuln report in the format the image asks for.
 5:45  point scrounging (bottom of this guide).
 5:50  .\cbptwindows.ps1 -Phase checklist and work the list by hand.

 WHERE THE POINTS ACTUALLY LIVE
 -----------------------------
  1. Forensic questions    -- ~8 pts each, trivial once you know where to look
  2. README tasks          -- explicitly listed, fully in your control
  3. Users / groups        -- unauthorized admin, guest on, blank password,
                              RID-500 clone, hidden account, never-expiring pw
  4. Malware / persistence -- Run keys, IFEO debuggers, sticky keys,
                              Startup folder, scheduled tasks, service
                              binPaths, WMI subscriptions, hosts file
  5. Password + lockout + audit policy (secedit + auditpol)
  6. UAC, Defender, firewall, Windows Update
  7. Critical services UP and correctly configured
  8. Registry long tail (LSA, SMB signing, TLS, autorun, hidden files,
     PowerShell logging)
  9. Share + NTFS permissions
 10. PII / policy violations found and documented

 HOW TO LOSE POINTS (read this twice)
 ------------------------------------
  * deleting a user the README authorizes. often unrecoverable.
  * deleting business documents, PII files, or the report file itself.
  * disabling or firewall-blocking a critical service or its port.
  * clearing event logs. looks like the attacker, destroys your evidence.
  * breaking the image so it needs re-extraction. re-extraction costs the
    clock, and the clock is the whole competition.
  * locking yourself out: deny rights on your own account, blocking
    cmd/powershell, "deny everyone" NTFS on C:\, disabling the account you
    are logged in as.
  * half-applied changes: edited a config, never restarted the service, so
    the RUNNING config is still the vulnerable one. that scores zero.
  * changing a password and not writing it down.

 BACKDOOR / PERSISTENCE HUNT (run these, in this order)
 -------------------------------------------------------
   net user                                     who exists
   net localgroup administrators                who is admin
   wmic useraccount get name,sid                cross-check for hidden accounts
   reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
       Shell must be explorer.exe, Userinit exactly userinit.exe
   Get-ItemProperty 'HK*:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run*'
   reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /s /v Debugger
       debugger on sethc/utilman/osk = shell hijack
   schtasks /query /fo LIST /v | findstr /i "Task To Run"
   Get-CimInstance Win32_Service | ? { $_.PathName -notmatch 'system32|program files' }
   Get-WmiObject -Namespace root\subscription -Class __EventFilter
   Get-WmiObject -Namespace root\subscription -Class __EventConsumer
   Get-NetTCPConnection -State Listen | sort LocalPort
   Get-CimInstance Win32_Process | ft ProcessId,ParentProcessId,Name,CommandLine -auto -wrap
   Get-ChildItem "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
   Get-Content C:\Windows\System32\drivers\etc\hosts
   Get-MpThreatDetection | Format-List
   Get-ChildItem $env:TEMP, "C:\Users\Public", "$env:APPDATA" -Recurse -Include *.exe,*.bat,*.vbs,*.ps1
   dir C:\ /a /s /o-d | more                     newest files first
   Get-Item <file> -Stream Zone.Identifier | Get-Content    where it came from
   Get-AuthenticodeSignature C:\Windows\System32\sethc.exe   sticky keys swap

 FORENSIC QUESTION STAPLES (Windows)
 -----------------------------------
   "hash of file X"             Get-FileHash X -Algorithm SHA256
   "what program ran at T"      C:\Windows\Prefetch\*.pf, Security 4688
                                (we enabled cmdline logging -> 4688 has the command)
   "what did they download"    %APPDATA%\...\Recent, browser History /
                                places.sqlite, Zone.Identifier ADS on the file
   "what device was plugged in" HKLM\SYSTEM\MountedDevices,
                                HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR,
                                C:\Windows\INF\setupapi.dev.log
   "what IP connected to us"    C:\Windows\System32\LogFiles\Firewall\pfirewall.log,
                                Security 4624 LogonType 3
   "who logged on and when"     Security 4624 / 4634 / 4672, net user <name>
   "who was added to admins"    Security 4728/4732 (group add), 4720 (user created)
   "what did they delete"       C:\$Recycle.Bin, Security 1102 (log cleared!)
   "hidden data in an image"    exiftool, look for data after PNG IEND / JPEG
                                EOI; Get-Content -Encoding Byte | Select -Last 100
   "decode this blob"           certutil -decode in.txt out.txt
                                [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s))
   "what is in this pcap"       Wireshark: follow TCP stream, http.request,
                                dns.qry.name; strings f.pcap | findstr /i "pass user"

   event IDs worth memorizing:
     4624 logon (type 2=local, 3=network, 10=RDP)   4625 failed logon
     4634 logoff        4672 admin logon            4688 process creation
     4720 user created  4722 enabled  4726 deleted   4728/4732 added to group
     1102 audit log cleared   (that is a finding all by itself)

 POINT SCROUNGING WITH TIME LEFT
 -------------------------------
   legal notice banner, screen saver lock, show hidden files + extensions,
   disable autorun, event log sizes, disable last-user display, require
   CTRL+ALT+DEL, remove Everyone from shares, disable guest, password
   history, audit removable storage, PowerShell script block logging,
   TLS cipher order, WDigest off, LSA PPL, Remote Assistance off, Office
   macros blocked, crash dumps off, LOLBin egress blocks. all of these are
   one registry key or one firewall rule each and they add up.

 HABITS THAT WIN ROUNDS
 ----------------------
   * screenshot everything before you change it. evidence disappears.
   * keep a running notepad of every vuln, in the format the scoring
     report wants. free points at the end of the round.
   * when you edit a service config: restart it, then verify it listens
     (Get-NetTCPConnection / netstat). an unapplied config scores zero.
   * if a check looks weird, think like the attacker for 60 seconds:
     "how would I keep access to this box?" then go look for exactly that.
   * test this script on a practice image first. always.
'@
    Write-Host $help
}

# ------------------------------------------------------------------------------
# final manual checklist -- read only. the README and the forensic questions
# are where the remaining points are, and no script can read them for you.
# ------------------------------------------------------------------------------
function Show-Checklist {
    Write-Banner 'FINAL MANUAL CHECKLIST'
    $text = @'
  Work through this with the README and the scoring report open. Nothing here
  changes the system; it is a prompt list plus a live snapshot.

  1. AUTHORIZED USERS
     - Compare users.txt / admins.txt against the README, not against memory.
     - Remove or disable every account the README does not authorize.
     - Check for extra administrators, RID-500 clones, hidden accounts, blank
       passwords, and password-never-expires flags.
     - Change every remaining user's password. Write the new one down.

  2. GROUP MEMBERSHIP / PRIVILEGE
     - net localgroup administrators; remove anyone not authorized.
     - Check Remote Desktop Users, Backup Operators, and Hyper-V Administrators.
     - Look for Deny logon rights that would lock out an authorized user.

  3. SERVICES + PORTS
     - Get-NetTCPConnection -State Listen; compare to the README critical list.
     - Stop and disable anything unnecessary. NEVER stop a scored service.
     - After every config edit: restart the service and confirm it listens.
     - Check Get-Service for stopped automatic services and event log errors.

  4. PERSISTENCE
     - Run keys, IFEO Debugger values, Startup folders, scheduled tasks,
       services with unusual binPaths, WMI subscriptions, hosts file.
     - Check for sticky-keys / utilman / osk debugger hijacks.
     - Check user profiles for recent executables, scripts, and media.
     - Do not delete evidence until the forensic questions are answered.

  5. LOGS + FORENSIC QUESTIONS
     - Answer them BEFORE hardening rotates evidence; never clear a log.
     - Security 4624/4625/4672/4688/4720/4728/4732/1102.
     - Prefetch, USBSTOR, mounted devices, browser history, Zone.Identifier.
     - Put the answers and evidence in the report the image asks for.

  6. FIREWALL / REMOTE ACCESS
     - Firewall on for Domain/Private/Public, inbound default Block.
     - Explicit allow only for the ports the README calls critical.
     - Remote Assistance off; RDP disabled unless it is a critical service.
     - WinRM TrustedHosts must not be '*'.

  7. DEFENDER + UPDATES
     - Real-time protection on, signatures current, no suspicious exclusions.
     - Windows Update service enabled and pending updates installed.
     - Reboot with enough clock left to re-verify every critical service.

  8. PATCH + POLICY
     - Password length/age/history, lockout threshold/duration, audit policy.
     - SMBv1 off, SMB signing on, LLMNR off, clear-text passwords off.
     - Office macros blocked, autorun off, crash dumps off.
     - Re-run -Phase verify and fix every FAIL.

  9. REPORT + HANDOFF
     - Write down what changed, why, and which README task it satisfies.
     - Screenshot the scoring report before and after.
     - Keep the evidence, backup, and transcript folders until the round ends.
'@
    Write-Host $text

    Write-CP 'local accounts' 'step'
    try {
        Get-CPUsers | Select-Object Name,Enabled,PasswordRequired,PasswordLastSet,LastLogon,SID |
            Format-Table -Auto | Out-String -Width 220 | Write-Host
    } catch { Write-CP 'could not enumerate local accounts' 'warn' }

    Write-CP 'administrators' 'step'
    try {
        Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop |
            Select-Object Name,ObjectClass,PrincipalSource | Format-Table -Auto | Out-String -Width 220 | Write-Host
    } catch {
        try { & net.exe localgroup Administrators 2>&1 | Write-Host } catch {}
    }

    Write-CP 'listening ports' 'step'
    try {
        Get-NetTCPConnection -State Listen -ErrorAction Stop | Sort-Object LocalPort -Unique |
            Select-Object LocalAddress,LocalPort,OwningProcess -First 80 | Format-Table -Auto | Out-String -Width 220 | Write-Host
    } catch {
        try { & netstat.exe -ano 2>&1 | Select-String 'LISTENING' | Select-Object -First 80 | Write-Host } catch {}
    }

    Write-CP 'enabled scheduled tasks (first 40)' 'step'
    try {
        Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.State -ne 'Disabled' } |
            Select-Object TaskName,TaskPath,State -First 40 | Format-Table -Auto | Out-String -Width 220 | Write-Host
    } catch { Write-CP 'Get-ScheduledTask unavailable' 'warn' }

    Write-CP 'SMB shares' 'step'
    try { Get-SmbShare -ErrorAction Stop | Select-Object Name,Path,Description | Format-Table -Auto | Out-String -Width 220 | Write-Host } catch {}

    Write-CP 'recent failed logons (4625, last 24h)' 'step'
    try {
        Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=4625; StartTime=(Get-Date).AddDays(-1) } `
            -MaxEvents 15 -ErrorAction Stop | Select-Object TimeCreated,Id,ProviderName |
            Format-Table -Auto | Out-String -Width 220 | Write-Host
    } catch { Write-CP 'no readable 4625 events (permissions or no failures)' 'info' }

    Write-CP 'Defender threat history' 'step'
    try {
        $t = @(Get-MpThreatDetection -ErrorAction Stop)
        if ($t.Count -eq 0) { Write-CP 'no recorded threat detections' 'ok' }
        else { $t | Select-Object -First 20 InitialDetectionTime,ThreatID,Resources | Format-List | Out-String | Write-Host }
    } catch { Write-CP 'Defender threat history unavailable' 'warn' }

    $reboot = @()
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $reboot += 'CBS pending' }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $reboot += 'Windows Update required' }
    $pfr = Get-CPReg -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations'
    if ($null -ne $pfr -and @($pfr).Count -gt 0) { $reboot += 'pending file rename' }
    if ($reboot.Count -gt 0) { Write-CP ("reboot pending: " + ($reboot -join '; ')) 'warn' }
    else { Write-CP 'no reboot pending' 'info' }

    Write-CP ("evidence: {0}" -f $script:EvDir) 'ok'
    Write-CP ("backup:   {0}" -f $script:BkDir) 'ok'
    Write-CP ("log:      {0}" -f $script:LogFile) 'ok'
    Add-Finding -Id 'CHECKLIST' -Area 'Checklist' -Status 'INFO' -Detail 'manual checklist printed' `
        -Hint 'The remaining points are in the README, the forensic questions, and the services you verify by hand.'
}

# ------------------------------------------------------------------------------
# interactive menu
# ------------------------------------------------------------------------------
function Show-Menu {
    while ($true) {
        Write-Banner ("cbptwindows $script:Version  --  $script:Hostname")
        $tags = ''
        if ($Aggressive) { $tags += ' [AGGRESSIVE]' }
        if ($Paranoid)   { $tags += ' [PARANOID]' }
        if ($script:Dry) { $tags += ' [DRY RUN]' }
        if ($DisableBuiltinAdmin) { $tags += ' [ADMIN-OFF]' }
        if ($NoLolbinBlocks)      { $tags += ' [NO-LOLBIN]' }
        if ($FirewallFile)        { $tags += ' [FW-IMPORT]' }
        if ($tags) { Write-Host ("   mode:{0}" -f $tags) -ForegroundColor Yellow }
        Write-Host ''
        Write-Host '   r) recon + evidence dump      (read only, safe)'  -ForegroundColor White
        Write-Host '   b) backup only'                                    -ForegroundColor White
        Write-Host '   c) final manual checklist    (read only)'          -ForegroundColor White
        Write-Host '   1) users + local security policy (users.txt/admins.txt + secedit)' -ForegroundColor White
        Write-Host '   2) registry hardening (LSA/UAC/SMB/TLS/PS logging)' -ForegroundColor White
        Write-Host '   3) network / firewall / SMB'                       -ForegroundColor White
        Write-Host '   4) services'                                       -ForegroundColor White
        Write-Host '   5) defender + audit + updates'                     -ForegroundColor White
        Write-Host '   6) installed apps (IIS/Apache/MySQL)'              -ForegroundColor White
        Write-Host '   7) file inventory (media/PII/exes, no deletes)'    -ForegroundColor White
        Write-Host '   v) verify + scorecard'                              -ForegroundColor White
        Write-Host '   a) RUN ALL (backup -> recon -> harden -> verify)'  -ForegroundColor Green
        Write-Host '   h) hints: how to max the score'                     -ForegroundColor Cyan
        Write-Host ("   x) toggle -Aggressive   (currently: {0})" -f [bool]$Aggressive) -ForegroundColor $(if($Aggressive){'Yellow'}else{'White'})
        Write-Host ("   p) toggle -Paranoid     (currently: {0})" -f [bool]$Paranoid)   -ForegroundColor $(if($Paranoid){'Yellow'}else{'White'})
        Write-Host ("   d) toggle -DryRun        (currently: {0})" -f $script:Dry)      -ForegroundColor $(if($script:Dry){'Yellow'}else{'White'})
        Write-Host '   q) quit'                                               -ForegroundColor DarkGray
        Write-Host ''
        $c = ''
        try { $c = (Read-Host '  pick one').Trim().ToLower() } catch { return }
        switch -Regex ($c) {
            '^r' { Invoke-Recon;       Export-Report }
            '^b' { New-CPBackup }
            '^c' { Show-Checklist }
            '^1' { Invoke-Users;       Export-Report }
            '^2' { Invoke-Registry;    Export-Report }
            '^3' { Invoke-Network;     Export-Report }
            '^4' { Invoke-Services;    Export-Report }
            '^5' { Invoke-Defender;    Export-Report }
            '^6' { Invoke-Apps;        Export-Report }
            '^7' { Invoke-Files;       Export-Report }
            '^v' { Invoke-Verify;      Export-Report }
            '^a' {
                if (Confirm-CP 'Run the full safe pass now? (backup, recon, users, registry, network, services, defender, apps, files, verify, checklist)') {
                    New-CPBackup
                    Invoke-Recon
                    Invoke-Users
                    Invoke-Registry
                    Invoke-Network
                    Invoke-Services
                    Invoke-Defender
                    Invoke-Apps
                    Invoke-Files
                    Invoke-Verify
                    Export-Report
                    Show-Checklist
                }
            }
            '^h' { Show-Hints }
            '^x' { $script:Aggressive = -not $script:Aggressive }
            '^p' { $script:Paranoid   = -not $script:Paranoid }
            '^d' { $script:Dry        = -not $script:Dry }
            '^q' { Write-CP 'bye. good luck on the round.' 'info'; return }
            default { Write-CP 'huh?' 'warn' }
        }
        Write-Host ''
        try { Read-Host '  press enter to go back to the menu' | Out-Null } catch { return }
    }
}

# ------------------------------------------------------------------------------
# main
# ------------------------------------------------------------------------------
function Main {
    if ($Hints) {
        Write-Banner ("cbptwindows $script:Version   |   " + $script:Hostname)
        Show-Hints
        return
    }

    if (-not (Test-Admin)) {
        Write-Banner ("cbptwindows $script:Version   |   " + $script:Hostname)
        Write-CP 'you are not running elevated. right-click PowerShell -> Run as administrator.' 'err'
        Write-CP 'most of this silently fails otherwise. -Hints works without elevation.' 'err'
        if (-not $Force) { try { Read-Host 'press enter to exit' | Out-Null } catch {} }
        exit 1
    }

    try { Initialize-CPArtifacts }
    catch {
        Write-Banner ("cbptwindows $script:Version   |   " + $script:Hostname)
        Write-CP ("could not initialize private artifacts: " + $_.Exception.Message) 'err'
        Write-CP 'Use a local fixed NTFS/ReFS WorkRoot owned by SYSTEM/Administrators.' 'err'
        exit 1
    }

    try { Start-Transcript -Path (Join-Path $script:Root ("transcript-" + $script:Stamp + ".txt")) -Force -ErrorAction SilentlyContinue | Out-Null } catch {}

    Write-Banner ("cbptwindows $script:Version   |   " + $script:Hostname + "   |   " + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
    $tier = 'DEFAULT (safe)'
    if ($Paranoid)   { $tier = 'PARANOID (read only)' }
    elseif ($Aggressive) { $tier = 'AGGRESSIVE' }
    Write-CP ("tier: {0}{1}" -f $tier, $(if ($Force) { ' [non-interactive]' } else { '' })) 'head'
    if ($script:Dry) { Write-CP 'dry-run: nothing on the system will change' 'warn' }

    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    if ($os) { Write-CP ("{0} ({1}) -- installed {2}" -f $os.Caption, $os.Version, $os.InstallDate) 'info' }
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        Write-CP 'PowerShell < 5.1 detected. Get-LocalUser / Get-SmbShare fall back or get skipped.' 'warn'
    }

    if ($Restore) { Restore-CPBackup -Path $Restore; try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch {}; return }

    switch ($Phase) {
        'menu'     { Show-Menu }
        'recon'    { if (-not ($Paranoid -or $NoBackup)) { New-CPBackup }; Invoke-Recon; Export-Report }
        'users'    { if (-not ($Paranoid -or $NoBackup)) { New-CPBackup }; Invoke-Users; Export-Report }
        'registry' { Invoke-Registry; Export-Report }
        'network'  { Invoke-Network; Export-Report }
        'services' { Invoke-Services; Export-Report }
        'defender' { Invoke-Defender; Export-Report }
        'apps'     { Invoke-Apps; Export-Report }
        'files'    { Invoke-Files; Export-Report }
        'verify'   { Invoke-Verify; Export-Report }
        'report'   { Export-Report }
        'checklist' { Show-Checklist; Export-Report }
        'guide'    { Show-Hints }
        'all'      {
            if (-not ($Paranoid -or $NoBackup)) { New-CPBackup }
            Invoke-Recon
            Invoke-Users
            Invoke-Registry
            Invoke-Network
            Invoke-Services
            Invoke-Defender
            Invoke-Apps
            Invoke-Files
            Invoke-Verify
            Export-Report
            Show-Checklist
            Write-Banner 'DONE'
            Write-CP 'now go read the README again and answer the forensic questions.' 'warn'
            Write-CP 'then restart every critical service and confirm it is still listening.' 'warn'
            Write-CP ("evidence: {0}" -f $script:EvDir) 'ok'
            Write-CP ("backup:   {0}" -f $script:BkDir) 'ok'
            Write-CP ("log:      {0}" -f $script:LogFile) 'ok'
        }
    }
    try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch {}
}

Main
