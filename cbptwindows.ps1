<#
================================================================================
 cbptwindows.ps1 -- CyberPatriot Windows image triage + hardening helper
Usage:       Right-click PowerShell -> Run as Administrator -> .\windows_script.ps1
If blocked, right click file, properties, Unblock. If still blocked, run this in powershell: Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
================================================================================
 grew out of the team checklist over a bunch of practice rounds. it is NOT
 a magic point button: it automates the boring baseline every team can do,
 then tells you where the rest of the points are. the README and the
 forensic questions are still yours -- and they are worth more than
 anything in this file.

 --------------------------------------------------------------------------------
 WHAT IT DOES
 --------------------------------------------------------------------------------
   1. backs up everything it is about to touch into a timestamped folder,
      so a bad run is undoable (-Restore).
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
   * never deletes a user, a file, or a log. it flags, you decide.
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
   -DryRun      print what WOULD change. touch nothing.
   -Aggressive  also offers things that can break a critical service
                (RDP off, wide-open firewall rules, server services).
                read the README before using it.
   -Paranoid    recon + backup + verify only. zero changes.
   -Force       non-interactive: assumes yes on the confirms.

 --------------------------------------------------------------------------------
 USAGE (elevated PowerShell)
 --------------------------------------------------------------------------------
   powershell -NoProfile -ExecutionPolicy Bypass -File .\cbptwindows.ps1
   .\cbptwindows.ps1 -Phase all                # backup -> recon -> harden -> verify
   .\cbptwindows.ps1 -Phase recon -Paranoid    # look, do not touch
   .\cbptwindows.ps1 -Phase users              # one section
   .\cbptwindows.ps1 -DryRun -Phase all        # rehearsal run
   .\cbptwindows.ps1 -Hints                    # the point-scrounging guide
   .\cbptwindows.ps1 -Restore C:\CP\cbptwindows\backup\<stamp>

   sections: recon users registry network services defender apps files
             verify report all menu guide

   the users section reconciles local accounts against users.txt, admins.txt,
   and groups.txt placed next to this script (one name per line, copied from
   the README). templates get created on first run if they are missing.

 --------------------------------------------------------------------------------
 CHANGELOG
 --------------------------------------------------------------------------------
   0.9.x  team checklist -> script. secedit MERGE logic after we clobbered
          user rights nobody remembered setting and broke a practice image.
   1.0.0  merged the best of our other helpers: users.txt/admins.txt
          reconciliation, sticky-keys + IFEO backdoor checks, malware hunt
          in recon, -DryRun, needs-review.txt, the master hints guide.
   1.0.1  Get-Service .StartType does not exist on PS 5.1 -> start types
          now go through sc.exe with a cmdlet fallback.
   1.2.0  added User Rights Assignment audit + remediation, groups.txt +
          interactive group helper, non-default/hidden share detection +
          removal, WDigest real path + DisableDomainCreds=1 + RDP non-enable
          fixes, full SmartScreen + Windows Update + Office + null-session
          registry hardening, optional Windows features disabling, Windows
          OpenSSH hardening, Appx/winget/outdated-app + Invoke-Software,
          non-blocking Defender QuickScan (-SkipScan), targeted fast
          Zone.Identifier/recent-files/Invoke-Files scans, PSReadLine history
          + netcat/tool binary hunt, and expanded Invoke-Verify coverage.

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
                 'network','services','defender','apps','software','files','verify','report')]
    [string]$Phase = 'menu',

    [switch]$Aggressive,
    [switch]$Paranoid,
    [switch]$DryRun,
    [switch]$NoBackup,
    [switch]$Force,
    [switch]$Hints,
    [switch]$SkipScan,

    [string]$Restore = '',
    [string]$WorkRoot = 'C:\CP\cbptwindows',
    [string]$KeepServices = ''
)

# ------------------------------------------------------------------------------
# globals
# ------------------------------------------------------------------------------
$script:Version    = '1.2.0'
$script:Stamp      = Get-Date -Format 'yyyyMMdd-HHmmss'
$script:Root       = $WorkRoot
$script:EvDir      = Join-Path $WorkRoot 'evidence'
$script:BkDir      = Join-Path $WorkRoot ("backup\" + $script:Stamp)
$script:LogFile    = Join-Path $WorkRoot ("cbptwindows-" + $script:Stamp + ".log")
$script:ReviewFile = Join-Path $script:Root   'needs-review.txt'
$script:Findings   = New-Object System.Collections.Generic.List[object]
$script:Changed    = New-Object System.Collections.Generic.List[object]
$script:Hostname   = $env:COMPUTERNAME
$script:Dry        = [bool]$DryRun
$script:Agg        = [bool]$Aggressive
$script:Para       = [bool]$Paranoid
$script:BackupDone = $false

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
    try { Add-Content -Path $script:LogFile -Value ("$ts $Level`t$Message") -ErrorAction SilentlyContinue } catch {}
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
    try { Add-Content -Path $script:ReviewFile -Value ("- " + $Message) -ErrorAction SilentlyContinue } catch {}
    Write-CP ("review: {0}   [saved to needs-review.txt]" -f $Message) 'warn'
}

function Test-Admin {
    try {
        $id  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $pr  = New-Object System.Security.Principal.WindowsPrincipal($id)
        return $pr.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        try { return ((& whoami /groups 2>&1) -match 'S-1-16-12288|High Mandatory Level').Count -gt 0 } catch { return $false }
    }
}

function Confirm-CP {
    param([string]$Question)
    if ($Force)   { return $true }
    if ($script:Para -or $script:Dry) { return $false }
    Write-Host ''
    Write-Host ("  !! " + $Question) -ForegroundColor Yellow
    try {
        $r = Read-Host '  type YES to continue'
        return ($r -ceq 'YES')
    } catch { return $false }
}

# run a change block. dry-run prints, paranoid refuses, errors log instead
# of killing the whole run mid-competition.
function Invoke-CP {
    param([string]$What, [scriptblock]$Block)
    if ($script:Dry) { Write-CP ("[dry-run] {0}" -f $What) 'warn'; return $false }
    try { & $Block; Write-CP $What 'ok'; return $true }
    catch { Write-CP ("{0} -> {1}" -f $What, $_.Exception.Message) 'warn'; return $false }
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
    if ($script:Dry -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }
    $safe = ([IO.Path]::GetFullPath($Path) -replace '[:\\/]','_')
    $dest = Join-Path $script:BkDir ("files\" + $safe)
    New-Item -ItemType Directory -Path (Split-Path $dest -Parent) -Force -ErrorAction SilentlyContinue | Out-Null
    if (-not (Test-Path $dest)) {
        Copy-Item -LiteralPath $Path -Destination $dest -Force -ErrorAction SilentlyContinue
        # flattened path cannot be reversed reliably; keep the original for restore
        try { Set-Content -Path ($dest + '.path') -Value $Path -Encoding UTF8 } catch {}
    }
}

function Backup-RegKey {
    param([string]$Path)
    if ($script:Dry -or -not (Test-Path $Path)) { return }
    $native = $Path -replace '^HKLM:', 'HKLM' -replace '^HKCU:', 'HKCU'
    $safe   = $Path -replace '[^A-Za-z0-9]+','_'
    $dest   = Join-Path $script:BkDir ("registry\" + $safe + '.reg')
    New-Item -ItemType Directory -Path (Split-Path $dest -Parent) -Force -ErrorAction SilentlyContinue | Out-Null
    if (-not (Test-Path $dest)) { & reg.exe export $native $dest /y 2>&1 | Out-Null }
}

function Get-CPReg {
    param([string]$Path, [string]$Name)
    try { return (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name } catch { return $null }
}

function Set-CPReg {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [AllowEmptyCollection()][Parameter(Mandatory)]$Value,
        [ValidateSet('DWord','QWord','String','ExpandString','MultiString','Binary')]
        [string]$Type = 'DWord',
        [string]$Id = '',
        [string]$Area = 'Registry'
    )
    if ($script:Para) { return $false }
    if ($script:Dry) { Write-CP ("[dry-run] reg {0}\{1} = {2}" -f $Path, $Name, ($Value -join ',')) 'warn'; return $false }
    try {
        if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
        $old = $null
        $hadOld = $false
        try { $old = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name; $hadOld = $true } catch {}
        if ($Type -eq 'MultiString') {
            if ($hadOld -and ((@($old) -join '|') -eq (@($Value) -join '|'))) {
                if ($Id) { Add-Finding -Id $Id -Area $Area -Status 'PASS' -Detail "$Name already correct" }
                return $true
            }
        } elseif ($hadOld -and (("$old") -eq ("$Value"))) {
            if ($Id) { Add-Finding -Id $Id -Area $Area -Status 'PASS' -Detail "$Name already correct" }
            return $true
        }
        Backup-RegKey $Path
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -ErrorAction Stop
        Register-Change -What ("$Path\$Name") -Old ("$old") -New ((@($Value) -join ','))
        if ($Id) { Add-Finding -Id $Id -Area $Area -Status 'PASS' -Detail "$Name set to $(@($Value) -join ',')" }
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

# ------------------------------------------------------------------------------
# service helpers.
# Set-Service -StartupType does NOT exist on Windows PowerShell 5.1, and
# Get-Service's .StartType property is missing on older builds. so start
# types go through sc.exe / Win32_Service, cmdlets are the fallback.
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
    if ($script:Para -or $script:Dry) {
        if ($script:Dry) { Write-CP ("[dry-run] sc config {0} start= {1}" -f $Name, $Type) 'warn' }
        return $false
    }
    $scType = switch ($Type) { 'Automatic' {'auto'} 'Manual' {'demand'} 'Disabled' {'disabled'} }
    $null = & sc.exe config $Name start= $scType 2>&1
    if ($LASTEXITCODE -eq 0) { return $true }
    try { Set-Service -Name $Name -StartupType $Type -ErrorAction Stop; return $true } catch {}
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
    try {
        return @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop |
            Where-Object { $_.ObjectClass -eq 'User' -and $_.PrincipalSource -eq 'Local' } |
            ForEach-Object { ($_.Name -split '\\')[-1] })
    } catch {
        try {
            return @(& net localgroup Administrators 2>$null | Select-Object -Skip 6 |
                Where-Object { $_ -and $_ -notmatch 'command completed' } | ForEach-Object { $_.Trim() })
        } catch { return @() }
    }
}

# one name per line, '#' starts a comment. template created if missing.
function Read-List {
    param([string]$Path, [string]$Template)
    if (-not (Test-Path -LiteralPath $Path)) {
        if ($script:Dry) { Write-CP ("[dry-run] would create template {0}" -f $Path) 'warn'; return @() }
        try { Set-Content -Path $Path -Value $Template -ErrorAction Stop } catch {}
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
    $tmp = Join-Path $env:TEMP ("gdn_pol_" + [guid]::NewGuid().ToString('N') + '.inf')
    # REGVALS is not a secedit area. [Registry Values] is part of
    # SECURITYPOLICY, which is why both commands use only these two areas.
    $null = & secedit.exe /export /cfg "$tmp" /areas SECURITYPOLICY USER_RIGHTS 2>&1
    if (-not (Test-Path $tmp)) { throw 'secedit /export produced no file' }
    return $tmp
}

function ConvertFrom-CPSid {
    param([string]$Entry)
    $raw = $Entry.Trim()
    if (-not $raw) { return '' }
    if ($raw.StartsWith('*')) { $raw = $raw.Substring(1) }
    if ($raw -match '^S-\d+-\d+') {
        try {
            $sidObj = New-Object System.Security.Principal.SecurityIdentifier($raw)
            return $sidObj.Translate([System.Security.Principal.NTAccount]).Value
        } catch { return $raw }
    }
    return $raw
}

function Get-CPUserRights {
    param([string]$InfPath = '')
    $cleanup = $false
    if (-not $InfPath) {
        $InfPath = Get-SeceditInf
        $cleanup = $true
    }
    $list = New-Object System.Collections.Generic.List[object]
    $inPriv = $false
    foreach ($line in (Get-Content -LiteralPath $InfPath -ErrorAction SilentlyContinue)) {
        $t = $line.Trim()
        if ($t -match '^\[(.+)\]$') {
            $inPriv = ($Matches[1] -ieq 'Privilege Rights')
            continue
        }
        if ($inPriv -and $t -match '^([^=]+)=(.*)$') {
            $right = $Matches[1].Trim()
            $rawVal = $Matches[2].Trim()
            $entries = @($rawVal -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            $resolved = @($entries | ForEach-Object { ConvertFrom-CPSid $_ })
            $list.Add([pscustomobject]@{
                Right       = $right
                RawEntries  = $entries
                Names       = $resolved
                RawValue    = $rawVal
            })
        }
    }
    if ($cleanup) { Remove-Item -LiteralPath $InfPath -Force -ErrorAction SilentlyContinue }
    return ,$list
}

function Set-SeceditValue {
    param(
        [System.Collections.Generic.List[string]]$Lines,
        [string]$Section, [string]$Key, [string]$Value
    )
    $inSec = $false; $lastIdx = -1; $secIdx = -1
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        $l = $Lines[$i].Trim()
        if ($l -match '^\[(.+)\]$') {
            if ($inSec) {
                $ins = if ($lastIdx -ge 0) { $lastIdx + 1 } else { $secIdx + 1 }
                $Lines.Insert($ins, "$Key = $Value")
                return $true
            }
            $inSec = ($Matches[1] -ieq $Section); $lastIdx = -1; $secIdx = $i; continue
        }
        if ($inSec) {
            if ($l -match '^([^=]+)=(.*)$') {
                if ($Matches[1].Trim() -ieq $Key) { $Lines[$i] = "$Key = $Value"; return $true }
                $lastIdx = $i
            }
        }
    }
    if ($inSec) {
        $ins = if ($lastIdx -ge 0) { $lastIdx + 1 } else { $secIdx + 1 }
        $Lines.Insert($ins, "$Key = $Value")
        return $true
    }
    $Lines.Add(''); $Lines.Add("[$Section]"); $Lines.Add("$Key = $Value")
    return $true
}

function Apply-SeceditInf {
    param([string]$InfPath)
    if ($script:Para) { return $true }
    if ($script:Dry) { Write-CP ("[dry-run] secedit /configure with {0}" -f $InfPath) 'warn'; return $false }
    $db = Join-Path $env:TEMP ("gdn_appl_" + [guid]::NewGuid().ToString('N') + '.sdb')
    $r = & secedit.exe /configure /db "$db" /cfg "$InfPath" /areas SECURITYPOLICY USER_RIGHTS /quiet 2>&1
    Remove-Item $db -Force -ErrorAction SilentlyContinue
    if ($LASTEXITCODE -ne 0) { Write-CP ("secedit /configure returned $LASTEXITCODE : $r" ) 'warn'; return $false }
    return $true
}
# ------------------------------------------------------------------------------
# backup / restore
# ------------------------------------------------------------------------------
function New-CPBackup {
    param([switch]$ForceBackup)
    if ($script:BackupDone -and -not $ForceBackup) { Write-CP "backup already taken this session ($script:BkDir)" 'info'; return }
    Write-Banner 'BACKUP'
    if ($NoBackup) { Write-CP 'skipped (-NoBackup)' 'warn'; return }
    New-Item -ItemType Directory -Path $script:BkDir -Force | Out-Null
    $b = $script:BkDir
    Write-CP "backup folder: $b"

    Invoke-CP 'backup registry hives' {
        foreach ($h in @('SOFTWARE','SYSTEM','SECURITY','SAM')) {
            $null = & reg.exe save "HKLM\$h" (Join-Path $b "$h.reg") /y 2>&1
            if ($LASTEXITCODE -ne 0) { Write-CP "could not save HKLM\$h (protected hive)" 'warn' }
        }
        $null = & reg.exe export 'HKCU\Software' (Join-Path $b 'HKCU-Software.reg') /y 2>&1
        if ($LASTEXITCODE -ne 0) { Write-CP 'could not export HKCU\Software' 'warn' }
        $null = & reg.exe export 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies' (Join-Path $b 'Policies.reg') /y 2>&1
        if ($LASTEXITCODE -ne 0) { Write-CP 'could not export the Policies key' 'warn' }
    }
    Invoke-CP 'backup local security policy' {
        $null = & secedit.exe /export /cfg (Join-Path $b 'secpol-before.inf') /quiet 2>&1
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path (Join-Path $b 'secpol-before.inf'))) {
            Write-CP 'secedit /export failed' 'warn'
        }
    }
    Invoke-CP 'backup firewall policy' {
        $null = & netsh advfirewall export (Join-Path $b 'firewall-before.wfw') 2>&1
        if ($LASTEXITCODE -ne 0) { Write-CP 'netsh advfirewall export failed' 'warn' }
    }
    Invoke-CP 'backup account + group state' {
        & net user       > (Join-Path $b 'net-user.txt') 2>&1
        & net localgroup > (Join-Path $b 'net-localgroup.txt') 2>&1
        Get-CPUsers | Export-Csv (Join-Path $b 'local-users.csv') -NoTypeInformation
        try { Get-LocalGroup | Export-Csv (Join-Path $b 'local-groups.csv') -NoTypeInformation } catch {}
        try {
            Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop |
                Export-Csv (Join-Path $b 'administrators.csv') -NoTypeInformation
        } catch {}
    }
    Invoke-CP 'backup service + task state' {
        Get-CimInstance Win32_Service |
            Select-Object Name,DisplayName,State,StartMode,StartName,PathName |
            Export-Csv (Join-Path $b 'services.csv') -NoTypeInformation
        & schtasks /query /fo LIST /v > (Join-Path $b 'schtasks.txt') 2>&1
    }
    Invoke-CP 'backup shares + hosts' {
        try { Get-SmbShare | Export-Csv (Join-Path $b 'shares.csv') -NoTypeInformation } catch {}
        & net share > (Join-Path $b 'net-share.txt') 2>&1
        Copy-Item C:\Windows\System32\drivers\etc\hosts (Join-Path $b 'hosts.txt') -Force -ErrorAction SilentlyContinue
    }
    Invoke-CP 'backup installed program list' {
        $paths = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                   'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
        Get-ItemProperty $paths -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } |
            Select-Object DisplayName,DisplayVersion,Publisher,InstallDate,UninstallString |
            Export-Csv (Join-Path $b 'programs.csv') -NoTypeInformation
    }
    Invoke-CP 'backup event log config + group policy report' {
        & wevtutil gl Security > (Join-Path $b 'evtlog-security.txt') 2>&1
        $null = & gpresult /h (Join-Path $b 'gpresult.html') /f 2>&1
    }
    $script:BackupDone = $true
    Write-CP ("backup complete ({0} files)" -f @(Get-ChildItem $b -Recurse -File -ErrorAction SilentlyContinue).Count) 'ok'
}

function Restore-CPBackup {
    param([string]$Path)
    if (-not (Test-Path $Path)) { Write-CP "no such backup: $Path" 'err'; return }
    Write-Banner "RESTORE FROM $Path"
    if (-not (Confirm-CP 'Restore policy / registry / firewall from this backup? Current state will be lost.')) { return }
    Invoke-CP 'restore secpol' {
        $inf = Get-ChildItem $Path -Filter 'secpol-before.inf' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($inf) { $null = & secedit.exe /configure /db "$env:TEMP\restore.sdb" /cfg $inf.FullName /quiet 2>&1 }
    }
    Invoke-CP 'restore firewall' {
        $wfw = Get-ChildItem $Path -Filter 'firewall-before.wfw' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($wfw) { $null = & netsh advfirewall restore $wfw.FullName 2>&1 }
    }
    Invoke-CP 'restore registry hives' {
        foreach ($h in @('SOFTWARE','SYSTEM','SECURITY','SAM')) {
            $f = Join-Path $Path "$h.reg"
            if (Test-Path $f) { $null = & reg.exe restore "HKLM\$h" "$f" /y 2>&1 }
        }
    }
    Invoke-CP 'restore registry values' {
        foreach ($rf in @(Get-ChildItem $Path -File -Filter '*.reg' -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -in @('HKCU-Software.reg','Policies.reg') })) {
            $null = & reg.exe import $rf.FullName 2>&1
        }
        $regRoot = Join-Path $Path 'registry'
        if (Test-Path $regRoot) {
            foreach ($rf in @(Get-ChildItem $regRoot -Filter '*.reg' -File -ErrorAction SilentlyContinue)) {
                $null = & reg.exe import $rf.FullName 2>&1
            }
        }
    }
    Invoke-CP 'restore files' {
        $fileRoot = Join-Path $Path 'files'
        if (Test-Path $fileRoot) {
            foreach ($bf in @(Get-ChildItem $fileRoot -File -ErrorAction SilentlyContinue |
                    Where-Object { $_.Extension -ne '.path' })) {
                $orig = Get-Content ($bf.FullName + '.path') -ErrorAction SilentlyContinue
                if ($orig) { Copy-Item -LiteralPath $bf.FullName -Destination $orig -Force -ErrorAction SilentlyContinue }
            }
        }
    }
    Write-CP 'restore issued. REBOOT the image so sshd-equivalents / LSA / firewall pick up the restored config.' 'warn'
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
    $rootGuard = $script:Root.TrimEnd('\') + '\'
    foreach ($r in $roots) {
        if (-not (Test-Path $r)) { continue }
        try {
            foreach ($f in (Get-ChildItem -Path $r -Recurse -Depth 3 -File -ErrorAction SilentlyContinue)) {
                if ($f.Extension -notin '.txt','.md','.rtf','.doc','.docx','.pdf') { continue }
                if ($f.Length -gt 512KB) { continue }      # a readme is never 512KB
                if ($f.FullName.StartsWith($rootGuard, [System.StringComparison]::OrdinalIgnoreCase)) { continue }
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
    New-Item -ItemType Directory -Path $script:EvDir -Force -ErrorAction SilentlyContinue | Out-Null
    $ev = $script:EvDir
    Write-CP "evidence -> $ev"

    Invoke-CP 'system summary' {
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
    Invoke-CP 'local accounts' {
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
            if ($u.Source -eq 'Get-LocalUser' -and $null -eq $u.PasswordExpires -and $u.Enabled) {
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
            # RID-500 clone: a differently-named account carrying the built-in
            # admin RID. classic backdoor, graded heavily.
            if ($u.SID -and $u.SID -match '-500$' -and $u.Name -ne 'Administrator') {
                Add-Finding -Id "USER-RID500-$($u.Name)" -Area 'Accounts' -Status 'FAIL' `
                    -Detail "$($u.Name) holds RID 500 (the built-in admin RID)" `
                    -Hint 'RID-500 under a different name is the classic cloned-admin backdoor. Screenshot it, report it, then deal with it.'
            }
        }

        # hidden accounts: visible to WMI but not to Get-LocalUser
        try {
            $names = @($rows | ForEach-Object { $_.Name })
            $cls = @(Get-CimInstance Win32_UserAccount -Filter 'LocalAccount=True' -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
            $hidden = @($cls | Where-Object { $_ -and ($names -notcontains $_) })
            if ($hidden.Count -gt 0) {
                Add-Finding -Id 'USER-HIDDEN' -Area 'Accounts' -Status 'FAIL' -Detail "hidden account(s): $($hidden -join ', ')" `
                    -Hint 'Accounts present in WMI but not Get-LocalUser (names ending in $ are normal) are a classic backdoor. Report + disable, do not delete.'
            } else {
                Add-Finding -Id 'USER-HIDDEN' -Area 'Accounts' -Status 'PASS' -Detail 'no hidden local accounts'
            }
        } catch {}
    }

    Invoke-CP 'group membership' {
        $g = New-Object System.Collections.Generic.List[object]
        foreach ($grp in @('Administrators','Users','Guests','Remote Desktop Users','Power Users',
                           'Backup Operators','Account Operators','Print Operators','Server Operators',
                           'Replicators','Cryptographic Operators','Network Configuration Operators',
                           'Distributed COM Users','Event Log Readers','Hyper-V Administrators',
                           'IIS_IUSRS','Performance Log Users')) {
            try {
                $m = @(Get-LocalGroupMember -Group $grp -ErrorAction Stop)
                foreach ($x in $m) {
                    $g.Add([pscustomobject]@{ Group=$grp; Member=$x.Name; SID=$x.SID.Value; Type=$x.ObjectClass })
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

    Invoke-CP 'user rights assignment audit' {
        $ur = Get-CPUserRights
        $ur | Select-Object Right,@{n='Accounts';e={$_.Names -join '; '}},RawValue |
            Export-Csv (Join-Path $ev '12-user-rights.csv') -NoTypeInformation
        $adminNames = @(Get-AdminMemberNames)
        $sensRights = @(
            'SeSecurityPrivilege','SeTakeOwnershipPrivilege','SeDebugPrivilege','SeTcbPrivilege',
            'SeBackupPrivilege','SeRestorePrivilege','SeLoadDriverPrivilege','SeImpersonatePrivilege',
            'SeAssignPrimaryTokenPrivilege','SeCreateTokenPrivilege','SeManageVolumePrivilege',
            'SeRemoteShutdownPrivilege','SeCreatePermanentPrivilege','SeLockMemoryPrivilege',
            'SeRelabelPrivilege','SeTrustedCredManAccessPrivilege','SeEnableDelegationPrivilege',
            'SeSyncAgentPrivilege'
        )
        foreach ($entry in $ur) {
            if ($entry.Right -notin $sensRights) { continue }
            $badAccts = New-Object System.Collections.Generic.List[string]
            foreach ($nm in $entry.Names) {
                $short = ($nm -split '\\')[-1]
                if ($short -match '^(Administrators|SYSTEM|LOCAL SERVICE|NETWORK SERVICE|SERVICE|WdiServiceHost)$') { continue }
                if ($short -match '^(Everyone|Anonymous Logon|ANONYMOUS LOGON|Guest|Guests|Users|Authenticated Users)$') {
                    $badAccts.Add($nm)
                } elseif ($adminNames -notcontains $short) {
                    $badAccts.Add($nm)
                }
            }
            if ($badAccts.Count -gt 0) {
                Add-Finding -Id "URIGHT-$($entry.Right)" -Area 'Policy' -Status 'FAIL' `
                    -Detail "$($entry.Right) granted to: $($badAccts -join ', ')" `
                    -Hint 'Non-admin user holding sensitive User Right (e.g. Manage auditing / Take ownership / Debug). Fix in Invoke-Users or secpol.msc.'
            }
        }
        foreach ($entry in $ur) {
            if ($entry.Right -in @('SeNetworkLogonRight','SeRemoteInteractiveLogonRight')) {
                foreach ($nm in $entry.Names) {
                    if ($nm -match '(?i)(^|\\)(Everyone|Guest|Guests|Anonymous Logon)$') {
                        Add-Finding -Id "URIGHT-$($entry.Right)" -Area 'Policy' -Status 'FAIL' `
                            -Detail "$($entry.Right) allows '$nm'" `
                            -Hint 'Remove Everyone/Guest/Anonymous from network/RDP logon rights in secpol.msc.'
                    }
                }
            }
        }
    }

    # ---- network --------------------------------------------------------
    Invoke-CP 'listening ports' {
        $rows = New-Object System.Collections.Generic.List[object]
        try {
            foreach ($x in (Get-NetTCPConnection -State Listen -ErrorAction Stop)) {
                $procName = ''
                try { $procName = (Get-Process -Id $x.OwningProcess -ErrorAction Stop).ProcessName } catch {}
                $rows.Add([pscustomobject]@{ Proto='TCP'; LocalAddress=$x.LocalAddress; Port=$x.LocalPort; PID=$x.OwningProcess; Process=$procName })
            }
        } catch {
            # Get-NetTCPConnection missing on some old images -> parse netstat
            foreach ($line in (& netstat -ano 2>&1)) {
                if ("$line" -notmatch 'LISTENING') { continue }
                $bits = @("$line" -split '\s+' | Where-Object { $_ })
                if ($bits.Count -lt 5) { continue }
                $la = $bits[1]
                $lp = 0
                if ($la.LastIndexOf(':') -gt 0) { [void][int]::TryParse($la.Substring($la.LastIndexOf(':')+1), [ref]$lp) }
                $pn = ''
                try { $pn = (Get-Process -Id $bits[4] -ErrorAction Stop).ProcessName } catch {}
                $rows.Add([pscustomobject]@{ Proto='TCP'; LocalAddress=$la; Port=$lp; PID=$bits[4]; Process=$pn })
            }
        }
        $rows | Sort-Object Port -Unique | Export-Csv (Join-Path $ev '20-listening.csv') -NoTypeInformation
        $rows | Sort-Object Port -Unique | Format-Table -Auto | Out-String -Width 200 | Set-Content (Join-Path $ev '20-listening.txt')
        & netstat -anob > (Join-Path $ev '20-netstat-anob.txt') 2>&1
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
    Invoke-CP 'persistence: run keys + winlogon' {
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
        $dump = New-Object System.Collections.Generic.List[object]
        foreach ($k in $keys) {
            if (-not (Test-Path $k)) { continue }
            $p = Get-ItemProperty $k
            foreach ($n in ($p.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' })) {
                $dump.Add([pscustomobject]@{ Key=$k; Name=$n.Name; Value=$n.Value })
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

    Invoke-CP 'persistence: IFEO debugger hijacks' {
        # the classic "press shift 5 times -> cmd.exe" trick lives here
        $ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
        $hits = @()
        if (Test-Path $ifeo) {
            foreach ($sub in (Get-ChildItem $ifeo -ErrorAction SilentlyContinue)) {
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

    Invoke-CP 'persistence: sticky keys + accessibility binaries' {
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

    Invoke-CP 'persistence: startup folders' {
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

    Invoke-CP 'persistence: scheduled tasks' {
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

    Invoke-CP 'persistence: services with odd binPaths' {
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

    Invoke-CP 'persistence: WMI event subscriptions' {
        $filt = @(Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue)
        $cons = @(Get-WmiObject -Namespace root\subscription -Class __EventConsumer -ErrorAction SilentlyContinue)
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
    Invoke-CP 'malware hunt: processes + backdoor tools + ps profiles' {
        Get-Process | Sort-Object CPU -Descending |
            Select-Object -First 15 Name,Id,CPU,Path | Format-Table -Auto |
            Out-String -Width 220 | Set-Content (Join-Path $ev '35-top-processes.txt')
        Get-Content (Join-Path $ev '35-top-processes.txt') | ForEach-Object { Write-Host ("   " + $_) }

        # full process command lines (catches nc -l -p / reverse shells / miners)
        $procs = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)
        $procs | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine |
            Export-Csv (Join-Path $ev '35-processes-full.csv') -NoTypeInformation
        foreach ($pr in $procs) {
            $cl = "$($pr.CommandLine)"
            if ($cl -match '(?i)\b(nc|nc64|ncat|netcat|socat|xmrig|mimikatz|pwdump|fgdump)\b|\s-e\s+(cmd|powershell)|-enc\b') {
                Add-Finding -Id "PROC-$($pr.ProcessId)" -Area 'Malware' -Status 'FAIL' `
                    -Detail "suspicious process [$($pr.Name) PID $($pr.ProcessId)]: $cl" `
                    -Hint 'Stop-Process -Id <PID> -Force, hash the binary, remove its persistence, and document it.'
            }
        }

        # targeted fast hunt for known backdoor / pentest binaries
        $toolNames = @('nc.exe','nc64.exe','ncat.exe','netcat.exe','socat.exe','mimikatz.exe',
                       'psexec.exe','procdump.exe','chisel.exe','xmrig.exe','pwdump*.exe','fgdump.exe')
        $toolRoots = New-Object System.Collections.Generic.List[string]
        foreach ($tr in @('C:\','C:\Tools','C:\Temp','C:\Windows\Temp','C:\ProgramData','C:\Users\Public')) {
            if (Test-Path $tr) { $toolRoots.Add($tr) }
        }
        foreach ($u in (Get-ChildItem C:\Users -Directory -ErrorAction SilentlyContinue)) {
            if ($u.Name -in @('Default','Default User','All Users')) { continue }
            foreach ($sub in @('Desktop','Downloads','Documents')) {
                $sp = Join-Path $u.FullName $sub
                if (Test-Path $sp) { $toolRoots.Add($sp) }
            }
        }
        $toolHits = New-Object System.Collections.Generic.List[object]
        foreach ($tr in $toolRoots) {
            $depthArgs = if ($tr -eq 'C:\') { @{ Depth = 1 } } else { @{} }
            foreach ($f in @(Get-ChildItem -Path $tr -File -Include $toolNames @depthArgs -Recurse:($tr -ne 'C:\') -ErrorAction SilentlyContinue)) {
                $toolHits.Add([pscustomobject]@{ FullName=$f.FullName; Length=$f.Length; LastWriteTime=$f.LastWriteTime })
            }
        }
        $toolHits | Sort-Object FullName -Unique | Export-Csv (Join-Path $ev '37-tool-binaries.csv') -NoTypeInformation
        if ($toolHits.Count -gt 0) {
            Add-Finding -Id 'MAL-TOOLS' -Area 'Malware' -Status 'FAIL' `
                -Detail "$($toolHits.Count) backdoor/hacking binary(ies) found (e.g. $($toolHits[0].FullName))" `
                -Hint 'Check evidence\37-tool-binaries.csv -- netcat/ncat/mimikatz drops are classic high-point backdoors.'
        } else {
            Add-Finding -Id 'MAL-TOOLS' -Area 'Malware' -Status 'PASS' -Detail 'no netcat/mimikatz/psexec tool binaries in common paths'
        }

        # PowerShell profile persistence check
        $psProfiles = New-Object System.Collections.Generic.List[string]
        foreach ($pp in @("$env:windir\System32\WindowsPowerShell\v1.0\profile.ps1",
                          "$env:windir\System32\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1")) {
            if (Test-Path $pp) { $psProfiles.Add($pp) }
        }
        foreach ($u in (Get-ChildItem C:\Users -Directory -ErrorAction SilentlyContinue)) {
            foreach ($pf in @('profile.ps1','Microsoft.PowerShell_profile.ps1')) {
                $up = Join-Path $u.FullName ("Documents\WindowsPowerShell\" + $pf)
                if (Test-Path $up) { $psProfiles.Add($up) }
            }
        }
        foreach ($pf in $psProfiles) {
            $body = Get-Content -LiteralPath $pf -Raw -ErrorAction SilentlyContinue
            if ($body -and $body.Trim().Length -gt 0) {
                Add-Finding -Id 'PERSIST-PSPROFILE' -Area 'Persistence' -Status 'WARN' `
                    -Detail "non-empty PowerShell profile: $pf" `
                    -Hint 'Inspect PowerShell profile scripts -- attackers use them to auto-launch payloads on shell startup.'
            }
        }

        # round "malware" is usually fake and AV misses it. the binary lives
        # somewhere writable -- temp, appdata, public, downloads. that is the
        # whole list of hiding places that matter.
        $sketchy = @("$env:TEMP", 'C:\Windows\Temp', 'C:\Users\Public', "$env:APPDATA", "$env:LOCALAPPDATA\Temp")
        $found = New-Object System.Collections.Generic.List[object]
        foreach ($d in $sketchy) {
            if (-not (Test-Path $d)) { continue }
            foreach ($f in @(Get-ChildItem $d -Recurse -Include *.exe,*.bat,*.cmd,*.vbs,*.ps1,*.js,*.jar -ErrorAction SilentlyContinue)) {
                $found.Add([pscustomobject]@{ FullName=$f.FullName; Length=$f.Length; LastWriteTime=$f.LastWriteTime })
            }
        }
        $found | Export-Csv (Join-Path $ev '36-sketchy-binaries.csv') -NoTypeInformation
        if ($found.Count -gt 0) {
            Add-Finding -Id 'MAL-SKETCHY' -Area 'Malware' -Status 'WARN' -Detail "$($found.Count) executable(s)/script(s) in temp/appdata/public" `
                -Hint 'Round malware usually hides exactly here. Kill the process, delete the file, THEN remove its persistence (run keys / startup / tasks).'
        } else {
            Add-Finding -Id 'MAL-SKETCHY' -Area 'Malware' -Status 'PASS' -Detail 'nothing executable in the usual hiding spots'
        }
    }

    # ---- shares (including hidden/custom $ shares!) ----------------------
    Invoke-CP 'shares and share ACLs' {
        $sh = @()
        try { $sh = @(Get-SmbShare -ErrorAction Stop) } catch {}
        $sh | Export-Csv (Join-Path $ev '40-shares.csv') -NoTypeInformation
        $aclAll = New-Object System.Collections.Generic.List[object]
        foreach ($s in $sh) {
            if ($s.Name -notmatch '^(?i)(ADMIN\$|IPC\$|print\$|SYSVOL|NETLOGON|[A-Z]\$)$') {
                Add-Finding -Id "SHARE-CUSTOM-$($s.Name)" -Area 'Shares' -Status 'FAIL' `
                    -Detail "non-default/hidden share '$($s.Name)' -> '$($s.Path)'" `
                    -Hint 'Hidden or custom shares (like USERS$) are scored unless required by README. Remove-SmbShare -Name <name> -Force (handled in network section).'
            }
            $acl = @(Get-SmbShareAccess -Name $s.Name -ErrorAction SilentlyContinue)
            foreach ($a in $acl) { $aclAll.Add($a) }
            foreach ($a in $acl) {
                if ($a.AccountName -match '(?i)everyone|authenticated users|^guest|anonymous' -and $a.AccessRight -match 'Full|Change') {
                    Add-Finding -Id "SHARE-$($s.Name)" -Area 'Shares' -Status 'FAIL' `
                        -Detail "$($s.Name): $($a.AccountName) has $($a.AccessRight) access" `
                        -Hint 'Everyone=Full on a share is a very common scored vuln. Revoke-SmbShareAccess / Grant-SmbShareAccess.'
                }
            }
            if ($s.Name -notmatch '^(?i)(ADMIN\$|IPC\$|print\$|[A-Z]\$)$') {
                try {
                    $ntfs = @(Get-Acl -LiteralPath $s.Path -ErrorAction Stop).Access
                    foreach ($n in $ntfs) {
                        if ("$($n.IdentityReference)" -match '(?i)everyone|^guest|anonymous' -and "$($n.FileSystemRights)" -match 'FullControl|Modify|Write') {
                            Add-Finding -Id "NTFS-$($s.Name)" -Area 'Shares' -Status 'WARN' `
                                -Detail "$($s.Name) NTFS ($($s.Path)): $($n.IdentityReference) = $($n.FileSystemRights)" `
                                -Hint 'NTFS perms are scored separately from share perms. Fix BOTH layers.'
                        }
                    }
                } catch {}
            }
        }
        $aclAll | Export-Csv (Join-Path $ev '40-share-acl.csv') -NoTypeInformation
    }

    # ---- recent files + PII (targeted to avoid AppData cache bloat) ------
    Invoke-CP 'recently modified files' {
        $since = (Get-Date).AddDays(-180)
        $exts = '\.(txt|doc|docx|xls|xlsx|pdf|png|jpg|jpeg|gif|bmp|zip|rar|7z|tar|gz|exe|dll|bat|ps1|vbs|js|db|sqlite|sql|kdbx|log|csv|xml|ini|conf|bak)$'
        $paths = New-Object System.Collections.Generic.List[string]
        foreach ($p in (Get-ChildItem C:\Users -Directory -ErrorAction SilentlyContinue)) {
            if ($p.Name -in @('Default','Default User','All Users')) { continue }
            foreach ($sub in @('Desktop','Downloads','Documents','Pictures','Music','Videos')) {
                $sp = Join-Path $p.FullName $sub
                if (Test-Path $sp) { $paths.Add($sp) }
            }
        }
        foreach ($extra in @('C:\Users\Public','C:\ProgramData','C:\inetpub','C:\Temp','C:\Windows\Temp','C:\Downloads')) {
            if (Test-Path $extra) { $paths.Add($extra) }
        }
        $rows = New-Object System.Collections.Generic.List[object]
        foreach ($pp in $paths) {
            foreach ($f in @(Get-ChildItem $pp -Recurse -File -ErrorAction SilentlyContinue)) {
                if ($f.LastWriteTime -gt $since -and $f.Extension -match $exts) {
                    $rows.Add([pscustomobject]@{
                        FullName=$f.FullName; Length=$f.Length; LastWriteTime=$f.LastWriteTime
                        CreationTime=$f.CreationTime; Extension=$f.Extension
                    })
                }
            }
        }
        $rows | Sort-Object LastWriteTime -Descending | Export-Csv (Join-Path $ev '50-recent-files.csv') -NoTypeInformation
        Write-CP "$($rows.Count) recently-modified candidate files catalogued" 'ok'

        $piiHits = New-Object System.Collections.Generic.List[object]
        foreach ($f in ($rows | Where-Object { $_.Extension -in '.txt','.csv','.log','.xml','.ini','.conf' } | Select-Object -First 500)) {
            try {
                $c = Get-Content $f.FullName -Raw -ErrorAction Stop
                if (-not $c) { continue }
                if ($c -match '\b\d{3}-\d{2}-\d{4}\b') { $piiHits.Add([pscustomobject]@{ File=$f.FullName; Type='SSN-pattern' }) }
                if ($c -match '(?i)(password|passwd|pwd|secret|api[_-]?key|token)\s*[:=]\s*\S{3,}') { $piiHits.Add([pscustomobject]@{ File=$f.FullName; Type='cleartext-credential' }) }
                if ($c -match '(?i)(card|visa|mastercard|amex|credit)' -and $c -match '\b(?:\d[ -]?){13,19}\b') { $piiHits.Add([pscustomobject]@{ File=$f.FullName; Type='card-pattern' }) }
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
    Invoke-CP 'forensic artifacts (prefetch/recent/USB/MOTW/PSHistory)' {
        $pfDir = Join-Path $ev 'prefetch'
        New-Item -ItemType Directory -Path $pfDir -Force -ErrorAction SilentlyContinue | Out-Null
        Copy-Item 'C:\Windows\Prefetch\*.pf' $pfDir -Force -ErrorAction SilentlyContinue
        $pf = @(Get-ChildItem C:\Windows\Prefetch -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)
        $pf | Select-Object Name,LastWriteTime,CreationTime | Export-Csv (Join-Path $ev '60-prefetch.csv') -NoTypeInformation
        $pf | Select-Object -First 30 | ForEach-Object {
            Write-Host ("   prefetch {0}  {1}" -f $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm'), $_.Name)
        }

        Remove-Item (Join-Path $ev '61-recent.csv'),(Join-Path $ev '66-jumplists.csv') -Force -ErrorAction SilentlyContinue
        $psHistOut = Join-Path $ev '67-ps-history.txt'
        if (Test-Path $psHistOut) { Remove-Item $psHistOut -Force -ErrorAction SilentlyContinue }
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
            $psh = Join-Path $u.FullName 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
            if (Test-Path $psh) {
                Add-Content $psHistOut ("===== " + $psh)
                Get-Content $psh -ErrorAction SilentlyContinue | Add-Content $psHistOut
                Add-Content $psHistOut ''
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

        # mark of the web: targeted to user docs/downloads (avoids AppData cache bloat)
        $zoi = New-Object System.Collections.Generic.List[object]
        $scanRoots = New-Object System.Collections.Generic.List[string]
        foreach ($u in (Get-ChildItem C:\Users -Directory -ErrorAction SilentlyContinue)) {
            if ($u.Name -in @('Default','Default User','All Users')) { continue }
            foreach ($sub in @('Desktop','Downloads','Documents')) {
                $sp = Join-Path $u.FullName $sub
                if (Test-Path $sp) { $scanRoots.Add($sp) }
            }
        }
        foreach ($sr in @('C:\Users\Public','C:\Temp','C:\Downloads')) {
            if (Test-Path $sr) { $scanRoots.Add($sr) }
        }
        foreach ($sr in $scanRoots) {
            foreach ($f in @(Get-ChildItem $sr -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 800)) {
                try {
                    $s = Get-Item $f.FullName -Stream Zone.Identifier -ErrorAction Stop
                    if ($s) { $zoi.Add([pscustomobject]@{ File=$f.FullName; Size=$s.Length; LastWrite=$f.LastWriteTime }) }
                } catch {}
            }
        }
        $zoi | Export-Csv (Join-Path $ev '65-zone-identifiers.csv') -NoTypeInformation
        if ($zoi.Count -gt 0) {
            Add-Finding -Id 'FORENSIC-ZOI' -Area 'Forensics' -Status 'INFO' -Detail "$($zoi.Count) file(s) carry a Mark-of-the-Web" `
                -Hint 'Get-Content <file> -Stream Zone.Identifier -- shows the download URL. Classic forensic answer.'
        }
    }

    # ---- programs / appx / outdated apps / hosts / update / defender -----
    Invoke-CP 'installed programs + store apps + outdated check' {
        $paths = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                   'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
                   'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*')
        $p = @(Get-ItemProperty $paths -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName })
        $p | Select-Object DisplayName,DisplayVersion,Publisher,InstallDate,InstallLocation,UninstallString |
            Sort-Object DisplayName | Export-Csv (Join-Path $ev '70-programs.csv') -NoTypeInformation
        $suspect = '(?i)teamviewer|ammyy|anydesk|logmein|vnc|tightvnc|realvnc|ultravnc|tigervnc|radmin|rustdesk|parsec|ngrok|hamachi|zerotier|nmap|zenmap|wireshark|fiddler|charles|winpcap|npcap|mimikatz|rubeus|sharphound|bloodhound|netcat|ncat|putty|filezilla|winscp|cyberduck|tftp|torrent|utorrent|bittorrent|qbittorrent|deluge|transmission|frostwire|vuze|xmrig|minergate|keylog|procexp|procmon|process hacker|nirsoft|pwdump|fgdump|quarks|psexec|hydra|john|hashcat|ophcrack|cain|abel|angry ip|angryip|advanced ip|advanced port|metasploit|burp|nessus|aircrack|sqlmap|nikto|gobuster|dirb|ettercap|bettercap|ghidra|x64dbg|ollydbg|cheat engine|autohotkey|wildtangent|windirstat|ccleaner|bonjour|tor browser|openvpn|emule|skype|discord|steam|epic games|battle\.net|riot|roblox|minecraft|origin|ea app|uplay|gog galaxy'
        foreach ($x in $p) {
            if ($x.DisplayName -match $suspect) {
                Add-Finding -Id "PROG-$($x.DisplayName)" -Area 'Software' -Status 'WARN' `
                    -Detail "installed: $($x.DisplayName) $($x.DisplayVersion)" `
                    -Hint 'Remote-access, p2p, games, bloatware, or attack/recon tools (e.g. WildTangent/WinDirStat/Wireshark). Check README, uninstall, and document.'
            }
        }

        # key commonly-scored third-party apps (version inventory + winget upgrade check)
        $watchRx = '(?i)notepad\+\+|firefox|chrome|edge|7-zip|vlc|python|openssh|putty|filezilla|winrar|adobe|gimp|libreoffice|thunderbird'
        $watch = @($p | Where-Object { $_.DisplayName -match $watchRx } | Select-Object DisplayName,DisplayVersion,Publisher)
        $outLines = New-Object System.Collections.Generic.List[string]
        $outLines.Add('=== Watched Third-Party App Versions ===')
        foreach ($w in $watch) { $outLines.Add(("{0,-45} {1}" -f $w.DisplayName, $w.DisplayVersion)) }
        if (Get-Command winget.exe -ErrorAction SilentlyContinue) {
            try {
                $outLines.Add('')
                $outLines.Add('=== winget upgrade ===')
                $wg = & winget.exe upgrade --accept-source-agreements 2>&1
                foreach ($wl in $wg) { $outLines.Add("$wl") }
            } catch {}
        }
        $outLines | Set-Content (Join-Path $ev '72-outdated-apps.txt')
        if ($watch.Count -gt 0) {
            Add-Finding -Id 'PROG-WATCH' -Area 'Software' -Status 'INFO' `
                -Detail "$($watch.Count) tracked app(s) inventoried in 72-outdated-apps.txt (Notepad++, browsers, 7-Zip, etc.)" `
                -Hint 'Outdated 3rd-party apps (Notepad++, Firefox, Chrome, 7-Zip) are frequently scored. Use -Phase software or update manually.'
        }

        # Microsoft Store / Appx packages
        try {
            $appx = @(Get-AppxPackage -AllUsers -ErrorAction Stop | Select-Object Name,Version,Publisher,PackageFullName)
            $appx | Export-Csv (Join-Path $ev '71-appx-packages.csv') -NoTypeInformation
            foreach ($ax in $appx) {
                if ($ax.Name -match '(?i)candycrush|solitaire|xboxgaming|wildtangent|minecraft|roblox|disney|tiktok|spotify|torrent') {
                    Add-Finding -Id "APPX-$($ax.Name)" -Area 'Software' -Status 'INFO' `
                        -Detail "Store app installed: $($ax.Name) ($($ax.Version))" `
                        -Hint 'Check if games/bloatware should be removed via Remove-AppxPackage.'
                }
            }
        } catch {}
    }

    Invoke-CP 'hosts file' {
        Copy-Item C:\Windows\System32\drivers\etc\hosts (Join-Path $ev 'hosts.txt') -Force -ErrorAction SilentlyContinue
        $h = @(Get-Content C:\Windows\System32\drivers\etc\hosts -ErrorAction SilentlyContinue | Where-Object { $_ -and $_ -notmatch '^\s*#' })
        foreach ($line in $h) {
            if ($line -notmatch '^\s*(127\.0\.0\.1|::1)\s+localhost(\s+.*)?$' -and $line -notmatch '^\s*127\.0\.1\.1\s') {
                Add-Finding -Id 'HOSTS' -Area 'Network' -Status 'WARN' -Detail "hosts entry: $($line.Trim())" `
                    -Hint 'Redirect entries in hosts are used for phishing and to break updates. Verify each against the README.'
            }
        }
    }

    Invoke-CP 'windows update + defender state' {
        $st = Get-CPStartType 'wuauserv'
        Add-Finding -Id 'WU' -Area 'Updates' -Status $(if ($st -eq 'Disabled') {'FAIL'} else {'PASS'}) `
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

    Invoke-CP 'event log + forensic security events' {
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

        # extract key forensic security events (4720, 4726, 4728, 4732, 4625)
        try {
            $secEvs = @(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=@(4720,4726,4728,4732,4625)} -MaxEvents 100 -ErrorAction Stop)
            $secEvs | Select-Object TimeCreated,Id,@{n='Summary';e={($_.Message -split "`r?`n")[0]}} |
                Format-Table -Auto | Out-String -Width 240 | Set-Content (Join-Path $ev '82-security-events-summary.txt')
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

    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    $isDC = ($cs.PartOfDomain -and $os.ProductType -eq 2)
    if ($isDC) {
        Add-Finding -Id 'POL-DC' -Area 'Policy' -Status 'WARN' -Detail 'this is a DOMAIN CONTROLLER' `
            -Hint 'Password/lockout policy on a DC comes from the Default Domain Policy GPO (gpmc.msc), not secedit. Also check for a Fine-Grained Password Policy.'
    }

    # ---- 1. reconcile accounts & groups against the README lists ----------
    $usersPath  = Join-Path $PSScriptRoot 'users.txt'
    $adminsPath = Join-Path $PSScriptRoot 'admins.txt'
    $groupsPath = Join-Path $PSScriptRoot 'groups.txt'
    $made = $false
    if (-not (Test-Path $usersPath))  { if (-not $script:Dry) { Set-Content $usersPath  '# standard (non-admin) users from the README, one per line'; $made = $true } }
    if (-not (Test-Path $adminsPath)) { if (-not $script:Dry) { Set-Content $adminsPath '# administrators from the README, one per line';            $made = $true } }
    if (-not (Test-Path $groupsPath)) { if (-not $script:Dry) { Set-Content $groupsPath '# custom groups from the README, format: GroupName:user1,user2'; $made = $true } }
    if ($made) {
        Write-CP 'created users.txt / admins.txt / groups.txt templates next to the script.' 'warn'
        Write-CP 'fill them in from the README, then run the users section again.' 'warn'
    }

    $admins = @(Read-List $adminsPath '# administrators from the README, one per line')
    $users  = @(Read-List $usersPath  '# standard (non-admin) users from the README, one per line')
    $groupsCfg = @(Read-List $groupsPath '# custom groups from the README, format: GroupName:user1,user2')
    $all = @($users + $admins)
    $me = $env:USERNAME

    if ($all.Count -gt 0) {
        foreach ($u in @(Get-CPUsers)) {
            $rid = 500; try { $rid = [int](($u.SID -split '-')[-1]) } catch {}
            if ($rid -in 500,501,503,504) { continue }        # built-ins, handled below
            if ($all -contains $u.Name) { continue }
            Write-CP ("'$($u.Name)' is not in users.txt / admins.txt (enabled: $($u.Enabled))" ) 'warn'
            if ($u.Name -eq $me) {
                Add-Review "you are logged in as '$me' but it is not on the lists -- re-read the README"
                continue
            }
            if ($script:Para -or $script:Dry) { Add-Review "unlisted account '$($u.Name)' (dry-run/paranoid: no action)"; continue }
            Write-Host ''
            $c = Read-Host '  (R)emove, (D)isable, or (S)kip [S]'
            $n = $u.Name
            if ($c -match '^[Rr]') {
                Invoke-CP "remove user '$n'" {
                    Remove-LocalUser -Name $n -ErrorAction Stop
                } | Out-Null
                Register-Change -What "user $n" -Old 'present' -New 'removed'
            } elseif ($c -match '^[Dd]') {
                Invoke-CP "disable user '$n'" {
                    Disable-LocalUser -Name $n -ErrorAction Stop
                } | Out-Null
                Register-Change -What "user $n" -Old 'enabled' -New 'disabled'
            }
        }

        # built-in accounts: guest (501) and the pseudo accounts get disabled,
        # never deleted. RID 500 (built-in admin) is left alone -- renaming or
        # disabling it breaks scored checks and can lock you out.
        foreach ($rid in 501,503,504) {
            Get-CPUsers | Where-Object { $_.SID -match ("-$rid`$") -and $_.Enabled } | ForEach-Object {
                $n = $_.Name
                Invoke-CP "disable built-in account '$n'" { Disable-LocalUser -Name $n -ErrorAction Stop } | Out-Null
            }
        }

        # administrators group: local users only. domain members are reported,
        # not touched -- demoting a domain admin is not your call.
        $current = @(Get-AdminMemberNames)
        foreach ($n in $current) {
            if ($admins -contains $n) { continue }
            if ($n -eq $me) {
                Add-Review "'$me' is an admin but is not in admins.txt -- check the README"
                continue
            }
            if ($script:Para -or $script:Dry) { Add-Review "admin '$n' is not in admins.txt (no action)"; continue }
            Write-Host ''
            $c = Read-Host "  '$n' is an Administrator but not in admins.txt. Demote? (y/N)"
            if ($c -match '^[Yy]') {
                Invoke-CP "remove '$n' from Administrators" {
                    Remove-LocalGroupMember -SID 'S-1-5-32-544' -Member $n -ErrorAction Stop
                } | Out-Null
                Register-Change -What "admin group: $n" -Old 'member' -New 'removed'
            } else {
                Add-Review "admin '$n' left in Administrators -- verify against the README"
            }
        }
        foreach ($n in $admins) {
            if ($current -notcontains $n -and (Get-CPUsers | Where-Object { $_.Name -eq $n })) {
                if ($script:Para -or $script:Dry) { Add-Review "'$n' should be an admin per admins.txt (no action)"; continue }
                Write-Host ''
                $c = Read-Host "  '$n' should be an admin per admins.txt. Add to Administrators? (y/N)"
                if ($c -match '^[Yy]') {
                    Invoke-CP "add '$n' to Administrators" {
                        Add-LocalGroupMember -SID 'S-1-5-32-544' -Member $n -ErrorAction Stop
                    } | Out-Null
                }
            }
        }

        # one strong password on every authorized account (optional)
        if (-not ($script:Para -or $script:Dry)) {
            Write-Host ''
            $c = Read-Host '  set ONE new strong password on every authorized account? (y/N)'
            if ($c -match '^[Yy]') {
                $p1 = Read-Host '  new password (10+ chars)' -AsSecureString
                $p2 = Read-Host '  again' -AsSecureString
                $a = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($p1))
                $b = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($p2))
                if ($a -ne $b -or $a.Length -lt 10) {
                    Write-CP 'passwords differ or are shorter than 10 chars - skipped' 'warn'
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
                                    Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $n -ErrorAction SilentlyContinue
                                    if ($admins -contains $n) { Add-LocalGroupMember -SID 'S-1-5-32-544' -Member $n -ErrorAction SilentlyContinue }
                                } | Out-Null
                            }
                        }
                    }
                    Write-CP 'passwords updated - write the new one down' 'ok'
                }
                $a = $null; $b = $null
            }
        }

        # password flags on every enabled account
        foreach ($u in @(Get-CPUsers | Where-Object { $_.Enabled })) {
            $n = $u.Name
            if ($null -eq $u.PasswordExpires) {
                Invoke-CP "let password expire for '$n'" {
                    Set-LocalUser -Name $n -PasswordNeverExpires $false -ErrorAction Stop
                } | Out-Null
            }
            if (-not $u.PasswordRequired) {
                Invoke-CP "require a password for '$n'" {
                    & net user $n /passwordreq:yes 2>&1 | Out-Null
                    if ($LASTEXITCODE -ne 0) { throw 'net user /passwordreq failed' }
                } | Out-Null
            }
        }
    } else {
        Write-CP 'users.txt / admins.txt are empty -- only built-in account fixes and policy will run.' 'warn'
        Add-Review 'users.txt/admins.txt empty: fill them from the README and re-run the users section'
    }

    # ---- 1b. custom groups from groups.txt + interactive group helper -----
    foreach ($gs in $groupsCfg) {
        $parts = $gs -split ':', 2
        $gName = $parts[0].Trim()
        if (-not $gName) { continue }
        $gMembers = @()
        if ($parts.Count -gt 1 -and $parts[1]) {
            $gMembers = @($parts[1] -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        }
        if (-not (Get-LocalGroup -Name $gName -ErrorAction SilentlyContinue)) {
            Invoke-CP "create local group '$gName'" { New-LocalGroup -Name $gName -ErrorAction Stop | Out-Null } | Out-Null
        }
        foreach ($gm in $gMembers) {
            $existing = @()
            try { $existing = @(Get-LocalGroupMember -Group $gName -ErrorAction Stop | ForEach-Object { ($_.Name -split '\\')[-1] }) } catch {}
            if ($existing -notcontains $gm) {
                Invoke-CP "add '$gm' to group '$gName'" { Add-LocalGroupMember -Group $gName -Member $gm -ErrorAction Stop } | Out-Null
            }
        }
    }
    if (-not ($script:Para -or $script:Dry -or $Force)) {
        Write-Host ''
        $cgAns = Read-Host '  create a custom local group or add members interactively? (y/N)'
        if ($cgAns -match '^[Yy]') {
            $cgName = (Read-Host '  group name (blank to skip)').Trim()
            if ($cgName) {
                if (-not (Get-LocalGroup -Name $cgName -ErrorAction SilentlyContinue)) {
                    Invoke-CP "create group '$cgName'" { New-LocalGroup -Name $cgName -ErrorAction Stop | Out-Null } | Out-Null
                }
                $cgMembers = Read-Host "  comma-separated users to add to '$cgName' (blank for none)"
                foreach ($gm in ($cgMembers -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
                    Invoke-CP "add '$gm' to '$cgName'" { Add-LocalGroupMember -Group $cgName -Member $gm -ErrorAction Stop } | Out-Null
                }
            }
        }
    }

    $acctNames = (@(Get-CPUsers) | ForEach-Object { $_.Name }) -join ', '
    Add-Finding -Id 'ACC-INVENTORY' -Area 'Accounts' -Status 'INFO' `
        -Detail ("local accounts: {0}" -f $acctNames) `
        -Hint 'Compare this list, one name at a time, against the README authorized-user list. Not authorized = remove it. Authorized = leave it alone. Removing an authorized user is one of the biggest penalties in the competition.'

    # ---- 2. secedit policy MERGE ------------------------------------------
    if (-not $isDC) {
        Write-CP 'merging local security policy (secedit)' 'step'
        Invoke-CP 'secedit policy merge (password/lockout/audit/registry values/user rights)' {
            $inf = Get-SeceditInf
            New-Item -ItemType Directory -Path $script:BkDir -Force -ErrorAction SilentlyContinue | Out-Null
            Copy-Item $inf (Join-Path $script:BkDir 'secpol-exported.inf') -Force -ErrorAction SilentlyContinue
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
            foreach ($k in $sa.Keys) { $null = Set-SeceditValue -Lines $lines -Section 'System Access' -Key $k -Value $sa[$k] }

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
                'MACHINE\System\CurrentControlSet\Control\Lsa\DisableDomainCreds'                   = '4,1'
                'MACHINE\System\CurrentControlSet\Control\Lsa\SCENoApplyLegacyAuditPolicy'          = '4,1'
                'MACHINE\System\CurrentControlSet\Services\LDAP\LDAPClientIntegrity'                 = '4,1'
                'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal'    = '4,1'
                'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SealSecureChannel'     = '4,1'
                'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\SignSecureChannel'    = '4,1'
                'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireStrongKey'     = '4,1'
                'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange'= '4,0'
                'MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\MaximumPasswordAge'   = '4,30'
                'MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters\RequireSecuritySignature' = '4,1'
                'MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters\EnableSecuritySignature'  = '4,1'
                'MACHINE\System\CurrentControlSet\Services\LanmanServer\Parameters\RestrictNullSessAccess'   = '4,1'
                'MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature' = '4,1'
                'MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\EnablePlainTextPassword'  = '4,0'
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
                'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\UndockWithoutLogon'         = '4,0'
                'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun'        = '4,255'
                'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments\SaveZoneInformation'  = '4,1'
            }
            foreach ($k in $rv.Keys) { $null = Set-SeceditValue -Lines $lines -Section 'Registry Values' -Key $k -Value $rv[$k] }

            # [Privilege Rights] -- safe guest denials + remediate non-admin abuse on sensitive privileges
            $pr = [ordered]@{
                'SeDenyNetworkLogonRight'           = '*S-1-5-32-546'
                'SeDenyInteractiveLogonRight'       = '*S-1-5-32-546'
                'SeDenyRemoteInteractiveLogonRight'  = '*S-1-5-32-546'
                'SeDenyBatchLogonRight'             = '*S-1-5-32-546'
                'SeDenyServiceLogonRight'           = '*S-1-5-32-546'
            }
            foreach ($k in $pr.Keys) { $null = Set-SeceditValue -Lines $lines -Section 'Privilege Rights' -Key $k -Value $pr[$k] }

            $curRights = Get-CPUserRights -InfPath $inf
            $adminNames2 = @(Get-AdminMemberNames)
            $adminOnlyRights = @(
                'SeSecurityPrivilege','SeTakeOwnershipPrivilege','SeDebugPrivilege',
                'SeBackupPrivilege','SeRestorePrivilege','SeLoadDriverPrivilege',
                'SeManageVolumePrivilege','SeRemoteShutdownPrivilege','SeRelabelPrivilege'
            )
            $noOneRights = @(
                'SeTcbPrivilege','SeCreateTokenPrivilege','SeTrustedCredManAccessPrivilege',
                'SeEnableDelegationPrivilege','SeCreatePermanentPrivilege','SeLockMemoryPrivilege',
                'SeSyncAgentPrivilege'
            )
            foreach ($ur in $curRights) {
                $targetDefault = $null
                if ($ur.Right -in $adminOnlyRights) { $targetDefault = '*S-1-5-32-544' }
                elseif ($ur.Right -in $noOneRights) { $targetDefault = '' }
                else { continue }

                $badNames = @()
                foreach ($nm in $ur.Names) {
                    $short = ($nm -split '\\')[-1]
                    if ($short -match '^(Administrators|SYSTEM)$') { continue }
                    if ($short -match '^(Everyone|Anonymous Logon|ANONYMOUS LOGON|Guest|Guests|Users|Authenticated Users)$' -or ($adminNames2 -notcontains $short)) {
                        $badNames += $nm
                    }
                }
                if ($badNames.Count -gt 0) {
                    $desc = if ($targetDefault) { 'Administrators only' } else { 'No One' }
                    Write-CP ("User Right {0} currently has unauthorized account(s): {1}" -f $ur.Right, ($badNames -join ', ')) 'warn'
                    if ($Force -or (Confirm-CP ("Reset User Right '{0}' to {1}?" -f $ur.Right, $desc))) {
                        $null = Set-SeceditValue -Lines $lines -Section 'Privilege Rights' -Key $ur.Right -Value $targetDefault
                        Register-Change -What "UserRight:$($ur.Right)" -Old ($ur.Names -join ',') -New $desc
                        Add-Finding -Id "URIGHT-FIX-$($ur.Right)" -Area 'Policy' -Status 'PASS' -Detail "$($ur.Right) reset to $desc"
                    }
                }
            }

            $out = Join-Path $script:BkDir 'secpol-hardened.inf'
            New-Item -ItemType Directory -Path $script:BkDir -Force -ErrorAction SilentlyContinue | Out-Null
            Set-Content -Path $out -Value $lines -Encoding Unicode
            if (-not (Apply-SeceditInf -InfPath $out)) { throw 'secedit /configure failed' }
            Remove-Item $inf -Force -ErrorAction SilentlyContinue
        }
        if (-not ($script:Para -or $script:Dry)) { Invoke-CP 'gpupdate /force' { & gpupdate /force 2>&1 | Out-Null } | Out-Null }

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
        Invoke-CP 'autologon check' {
            $wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
            $al = Get-CPReg -Path $wl -Name 'AutoAdminLogon'
            $pw = Get-CPReg -Path $wl -Name 'DefaultPassword'
            if ("$al" -eq '1' -or $pw) {
                Set-CPReg $wl 'AutoAdminLogon' 0 DWord -Id 'ACC-AUTOLOGON' -Area 'Accounts' | Out-Null
                foreach ($n in 'DefaultPassword','DefaultUserName','DefaultDomainName','AltDefaultUserName','AltDefaultDomainName') {
                    Remove-ItemProperty -Path $wl -Name $n -ErrorAction SilentlyContinue
                }
                Register-Change -What 'Winlogon autologon' -Old "AutoAdminLogon=$al" -New 'removed'
            }
        }
        Add-Finding -Id 'ACC-AUTOLOGON' -Area 'Accounts' -Status 'PASS' -Detail 'autologon checked'
        Add-Finding -Id 'POL-URIGHTS' -Area 'Policy' -Status 'INFO' -Detail 'User Rights Assignment not fully rewritten' `
            -Hint 'Open secpol.msc > Local Policies > User Rights Assignment and compare against the README (who can log on remotely, debug programs, act as part of the OS...). The script only set the Guest denials.'
    }
}
# ------------------------------------------------------------------------------
# registry hardening -- the stuff secedit does not reach
# ------------------------------------------------------------------------------
function Invoke-Registry {
    Write-Banner 'REGISTRY HARDENING'
    if ($script:Para) { Write-CP 'paranoid mode: registry pass skipped' 'warn'; return }

    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    Set-CPReg -Path $lsa -Name 'RestrictAnonymous'           -Value 1 -Id 'REG-RestrictAnonymous' -Area 'Registry' | Out-Null
    Set-CPReg -Path $lsa -Name 'RestrictAnonymousSAM'        -Value 1 -Id 'REG-RestrictAnonSAM'   -Area 'Registry' | Out-Null
    Set-CPReg -Path $lsa -Name 'NoLMHash'                    -Value 1 -Id 'REG-NoLMHash'          -Area 'Registry' | Out-Null
    Set-CPReg -Path $lsa -Name 'LMCompatibilityLevel'        -Value 5 -Id 'REG-LMCompat'          -Area 'Registry' | Out-Null
    Set-CPReg -Path $lsa -Name 'LimitBlankPasswordUse'       -Value 1 -Id 'REG-BlankPwUse'        -Area 'Registry' | Out-Null
    Set-CPReg -Path $lsa -Name 'EveryoneIncludesAnonymous'   -Value 0 -Id 'REG-EveryoneAnon'      -Area 'Registry' | Out-Null
    Set-CPReg -Path $lsa -Name 'ForceGuest'                  -Value 0 -Id 'REG-ForceGuest'        -Area 'Registry' | Out-Null
    Set-CPReg -Path $lsa -Name 'DisableDomainCreds'          -Value 1 -Id 'REG-DisableDomainCreds' -Area 'Registry' | Out-Null
    Set-CPReg -Path $lsa -Name 'SCENoApplyLegacyAuditPolicy' -Value 1 -Id 'REG-NoLegacyAudit'     -Area 'Audit' | Out-Null
    Set-CPReg -Path $lsa -Name 'UseMachineId'                -Value 1 | Out-Null
    # WDigest keeps cleartext passwords in LSASS -- both legacy and real SecurityProviders path
    Set-CPReg -Path "$lsa\WDigest" -Name 'UseLogonCredential' -Value 0 -Id 'REG-WDigest' -Area 'Registry' | Out-Null
    Set-CPReg -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -Value 0 -Id 'REG-WDigest-Real' -Area 'Registry' | Out-Null
    # LSA protection (run as PPL). needs a reboot, worth the point.
    $ppl = Get-CPReg -Path $lsa -Name 'RunAsPPL'
    if ($null -eq $ppl -or $ppl -lt 1) {
        Set-CPReg -Path $lsa -Name 'RunAsPPL' -Value 1 -Id 'REG-RunAsPPL' -Area 'Registry' | Out-Null
    } else {
        Add-Finding -Id 'REG-RunAsPPL' -Area 'Registry' -Status 'PASS' -Detail "RunAsPPL = $ppl"
    }
    Set-CPReg -Path "$lsa\MSV1_0" -Name 'NTLMMinClientSec'          -Value 537395200 -Id 'REG-NTLMMinClient' -Area 'Registry' | Out-Null
    Set-CPReg -Path "$lsa\MSV1_0" -Name 'NTLMMinServerSec'          -Value 537395200 -Id 'REG-NTLMMinServer' -Area 'Registry' | Out-Null
    Set-CPReg -Path "$lsa\MSV1_0" -Name 'allownullsessionfallback'   -Value 0 | Out-Null
    Set-CPReg -Path "$lsa\pku2u"  -Name 'AllowOnlineID'             -Value 0 | Out-Null

    $sm = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    Set-CPReg -Path "$sm\Kernel"            -Name 'ObCaseInsensitive'       -Value 1 | Out-Null
    Set-CPReg -Path "$sm\Memory Management" -Name 'ClearPageFileAtShutdown' -Value 1 -Id 'REG-ClearPagefile' -Area 'Registry' | Out-Null
    Set-CPReg -Path $sm                     -Name 'ProtectionMode'          -Value 1 | Out-Null
    Set-CPReg -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name 'CrashDumpEnabled' -Value 0 | Out-Null
    Set-CPReg -Path 'HKLM:\SOFTWARE\Microsoft\DirectPlayNATHelp\DPNHUPnP'  -Name 'UPnPMode' -Value 2 | Out-Null

    # ---- UAC & logon -------------------------------------------------------
    $pol = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    Set-CPReg -Path $pol -Name 'EnableLUA'                  -Value 1 -Id 'REG-UAC-EnableLUA'     -Area 'UAC' | Out-Null
    Set-CPReg -Path $pol -Name 'ConsentPromptBehaviorAdmin' -Value 2 -Id 'REG-UAC-ConsentAdmin'  -Area 'UAC' | Out-Null
    Set-CPReg -Path $pol -Name 'ConsentPromptBehaviorUser'  -Value 0 -Id 'REG-UAC-ConsentUser'   -Area 'UAC' | Out-Null
    Set-CPReg -Path $pol -Name 'PromptOnSecureDesktop'      -Value 1 -Id 'REG-UAC-SecureDesktop' -Area 'UAC' | Out-Null
    Set-CPReg -Path $pol -Name 'FilterAdministratorToken'   -Value 1 -Id 'REG-UAC-FilterAdmin'   -Area 'UAC' | Out-Null
    Set-CPReg -Path $pol -Name 'EnableInstallerDetection'   -Value 1 | Out-Null
    Set-CPReg -Path $pol -Name 'EnableVirtualization'       -Value 1 | Out-Null
    Set-CPReg -Path $pol -Name 'EnableSecureUIAPaths'       -Value 1 | Out-Null
    Set-CPReg -Path $pol -Name 'DisableCAD'                 -Value 0 -Id 'REG-CAD' -Area 'UAC' | Out-Null
    Set-CPReg -Path $pol -Name 'DontDisplayLastUserName'    -Value 1 -Id 'REG-LastUser' -Area 'UAC' | Out-Null
    Set-CPReg -Path $pol -Name 'ShutdownWithoutLogon'       -Value 0 -Id 'REG-ShutdownNoLogon' -Area 'UAC' | Out-Null
    Set-CPReg -Path $pol -Name 'UndockWithoutLogon'         -Value 0 | Out-Null
    Set-CPReg -Path $pol -Name 'NoConnectedUser'            -Value 3 | Out-Null
    Set-CPReg -Path $pol -Name 'InactivityTimeoutSecs'      -Value 900 | Out-Null
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
    Set-CPReg -Path $exp -Name 'NoDriveTypeAutoRun'     -Value 255 -Id 'REG-Autorun' -Area 'Registry' | Out-Null
    Set-CPReg -Path $exp -Name 'NoAutorun'              -Value 1 | Out-Null
    Set-CPReg -Path $exp -Name 'NoAutoplayfornonVolume' -Value 1 | Out-Null
    Set-CPReg -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -Value 255 | Out-Null

    $att = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments'
    Set-CPReg -Path $att -Name 'SaveZoneInformation'      -Value 1 -Id 'REG-ZoneInfo' -Area 'Registry' | Out-Null
    Set-CPReg -Path $att -Name 'HideZoneInfoOnProperties' -Value 1 | Out-Null
    Set-CPReg -Path $att -Name 'ScanWithAntiVirus'        -Value 3 | Out-Null

    # ---- RDP + Remote Assistance: enforce NLA/encryption without enabling RDP!
    $rdp    = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $rdpPol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
    Set-CPReg -Path "$rdp\WinStations\RDP-Tcp" -Name 'UserAuthentication' -Value 1 -Id 'REG-RDP-NLA' -Area 'RDP' | Out-Null
    Set-CPReg -Path "$rdp\WinStations\RDP-Tcp" -Name 'SecurityLayer'      -Value 2 | Out-Null
    Set-CPReg -Path "$rdp\WinStations\RDP-Tcp" -Name 'MinEncryptionLevel' -Value 3 -Id 'REG-RDP-Enc' -Area 'RDP' | Out-Null
    Set-CPReg -Path $rdpPol -Name 'fPromptForPassword'    -Value 1 -Id 'REG-RDP-Prompt' -Area 'RDP' | Out-Null
    Set-CPReg -Path $rdpPol -Name 'MinEncryptionLevel'    -Value 3 | Out-Null
    Set-CPReg -Path $rdpPol -Name 'SecurityLayer'         -Value 2 | Out-Null
    Set-CPReg -Path $rdpPol -Name 'UserAuthentication'    -Value 1 | Out-Null
    # Always disable Remote Assistance (frequently scored separately from RDP)
    $ra = 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance'
    Set-CPReg -Path $ra -Name 'fAllowToGetHelp'   -Value 0 -Id 'REG-RemoteAssist' -Area 'RDP' | Out-Null
    Set-CPReg -Path $ra -Name 'fAllowFullControl' -Value 0 | Out-Null

    $rdpCur = Get-CPReg -Path $rdp -Name 'fDenyTSConnections'
    if ($rdpCur -eq 1) {
        Set-CPReg -Path $rdpPol -Name 'fDenyTSConnections' -Value 1 -Id 'REG-RDP-Deny' -Area 'RDP' | Out-Null
    } elseif ($script:Agg -or (-not $Force -and (Confirm-CP 'RDP is currently ENABLED (fDenyTSConnections=0). Disable RDP? Say NO if README requires Remote Desktop.'))) {
        if (-not $script:Agg -or (Confirm-CP 'AGGRESSIVE: fully disable RDP? Do NOT do this if the README lists remote access as a critical service.')) {
            Set-CPReg -Path $rdp    -Name 'fDenyTSConnections' -Value 1 -Id 'REG-RDP-Deny' -Area 'RDP' | Out-Null
            Set-CPReg -Path $rdpPol -Name 'fDenyTSConnections' -Value 1 | Out-Null
        }
    } else {
        Add-Finding -Id 'REG-RDP-Deny' -Area 'RDP' -Status 'WARN' -Detail 'RDP currently enabled (NLA + high encryption enforced)' `
            -Hint 'If README does not require Remote Desktop, disable it (fDenyTSConnections=1) or run with -Aggressive.'
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

    # ---- SMB signing + null session hardening ----------------------------
    $srv  = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    $wkst = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
    Set-CPReg -Path $srv  -Name 'RequireSecuritySignature'  -Value 1 -Id 'REG-SMBSign-Server' -Area 'SMB' | Out-Null
    Set-CPReg -Path $srv  -Name 'EnableSecuritySignature'   -Value 1 | Out-Null
    Set-CPReg -Path $srv  -Name 'EnableInsecureGuestLogons' -Value 0 -Id 'REG-GuestLogons' -Area 'SMB' | Out-Null
    Set-CPReg -Path $srv  -Name 'RestrictNullSessAccess'    -Value 1 -Id 'REG-NullSess' -Area 'SMB' | Out-Null
    Set-CPReg -Path $srv  -Name 'NullSessionPipes'          -Value ([string[]]@()) -Type MultiString | Out-Null
    Set-CPReg -Path $srv  -Name 'NullSessionShares'         -Value ([string[]]@()) -Type MultiString | Out-Null
    Set-CPReg -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths' -Name 'Machine' -Value ([string[]]@()) -Type MultiString | Out-Null
    Set-CPReg -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths'      -Name 'Machine' -Value ([string[]]@()) -Type MultiString | Out-Null
    Set-CPReg -Path $wkst -Name 'RequireSecuritySignature'  -Value 1 -Id 'REG-SMBSign-Client' -Area 'SMB' | Out-Null
    Set-CPReg -Path $wkst -Name 'EnableSecuritySignature'   -Value 1 | Out-Null
    Set-CPReg -Path $wkst -Name 'EnablePlainTextPassword'   -Value 0 -Id 'REG-PlainTextSMB' -Area 'SMB' | Out-Null
    Set-CPReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation' -Name 'AllowInsecureGuestAuth' -Value 0 | Out-Null

    # ---- PrintNightmare (CVE-2021-34527) -------------------------------------
    # only administrators may install printer drivers; also keep the legacy
    # "AddPrinterDrivers" security option in the same state.
    Set-CPReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' `
        -Name 'RestrictDriverInstallationToAdministrators' -Value 1 -Id 'REG-PrintNightmare' -Area 'Registry' | Out-Null
    Set-CPReg -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Servers' `
        -Name 'AddPrinterDrivers' -Value 1 | Out-Null

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
    foreach ($proto in @('TLS 1.2','TLS 1.3')) {
        Set-CPReg -Path "$sch\$proto\Server" -Name 'Enabled'           -Value 1 | Out-Null
        Set-CPReg -Path "$sch\$proto\Server" -Name 'DisabledByDefault' -Value 0 | Out-Null
        Set-CPReg -Path "$sch\$proto\Client" -Name 'Enabled'           -Value 1 | Out-Null
        Set-CPReg -Path "$sch\$proto\Client" -Name 'DisabledByDefault' -Value 0 | Out-Null
    }
    Set-CPReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Cryptography\Configuration\SSL\00010002' -Name 'Functions' -Type String `
        -Id 'REG-CipherOrder' -Area 'TLS' `
        -Value 'TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256' | Out-Null
    foreach ($nd in @('HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319','HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319')) {
        Set-CPReg -Path $nd -Name 'SchUseStrongCrypto'       -Value 1 -Id 'REG-DotNetCrypto' -Area 'TLS' | Out-Null
        Set-CPReg -Path $nd -Name 'SystemDefaultTlsVersions' -Value 1 | Out-Null
    }

    # ---- powershell logging. graders love it, attackers hate it --------------
    $psl = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
    Set-CPReg -Path "$psl\ScriptBlockLogging" -Name 'EnableScriptBlockLogging'           -Value 1 -Id 'REG-PS-ScriptBlock' -Area 'Logging' | Out-Null
    Set-CPReg -Path "$psl\ScriptBlockLogging" -Name 'EnableScriptBlockInvocationLogging' -Value 1 | Out-Null
    Set-CPReg -Path "$psl\ModuleLogging"      -Name 'EnableModuleLogging'                -Value 1 -Id 'REG-PS-Module' -Area 'Logging' | Out-Null
    New-Item -Path "$psl\ModuleLogging\ModuleNames" -Force -ErrorAction SilentlyContinue | Out-Null
    Set-CPReg -Path "$psl\ModuleLogging\ModuleNames" -Name '*' -Value '*' -Type String | Out-Null
    Set-CPReg -Path "$psl\Transcription" -Name 'EnableTranscripting'    -Value 1 -Id 'REG-PS-Transcript' -Area 'Logging' | Out-Null
    Set-CPReg -Path "$psl\Transcription" -Name 'EnableInvocationHeader' -Value 1 | Out-Null
    Set-CPReg -Path "$psl\Transcription" -Name 'OutputDirectory' -Value (Join-Path $script:Root 'pslogs') -Type String | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $script:Root 'pslogs') -Force -ErrorAction SilentlyContinue | Out-Null

    # ---- smart screen + windows update policy + installer + Office + DEP ----
    Set-CPReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnableSmartScreen'     -Value 1 -Id 'REG-SmartScreen' -Area 'Registry' | Out-Null
    Set-CPReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'ShellSmartScreenLevel' -Value 'Block' -Type String | Out-Null
    Set-CPReg -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'SmartScreenEnabled' -Value 'RequireAdmin' -Type String -Id 'REG-SmartScreen-Explorer' -Area 'Registry' | Out-Null
    Set-CPReg -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost'  -Name 'EnableWebContentEvaluation' -Value 1 | Out-Null
    Set-CPReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter' -Name 'EnabledV9' -Value 1 | Out-Null
    Set-CPReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter' -Name 'PreventOverride' -Value 1 | Out-Null
    Set-CPReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter' -Name 'PreventOverrideAppRepUnknown' -Value 1 | Out-Null
    Set-CPReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Name 'SmartScreenEnabled'    -Value 1 | Out-Null
    Set-CPReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -Name 'SmartScreenPuaEnabled' -Value 1 | Out-Null

    $wuAu = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
    Set-CPReg -Path $wuAu -Name 'NoAutoUpdate'                -Value 0 -Id 'REG-WU' -Area 'Updates' | Out-Null
    Set-CPReg -Path $wuAu -Name 'AUOptions'                   -Value 4 | Out-Null
    Set-CPReg -Path $wuAu -Name 'AutoInstallMinorUpdates'     -Value 1 | Out-Null
    Set-CPReg -Path $wuAu -Name 'AutomaticMaintenanceEnabled' -Value 1 | Out-Null
    Set-CPReg -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update' -Name 'AUOptions' -Value 4 | Out-Null
    Set-CPReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name 'DisableWindowsUpdateAccess' -Value 0 | Out-Null
    Set-CPReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name 'ElevateNonAdmins' -Value 0 | Out-Null
    Set-CPReg -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoWindowsUpdate' -Value 0 | Out-Null

    Set-CPReg -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated' -Value 0 -Id 'REG-InstallerElevated' -Area 'Registry' | Out-Null
    Set-CPReg -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name 'AlwaysInstallElevated' -Value 0 | Out-Null

    # Office 16.0 macro / internet execution hardening
    foreach ($app in @('word','excel','powerpoint')) {
        $okKey = "HKCU:\Software\Policies\Microsoft\Office\16.0\$app\security"
        Set-CPReg -Path $okKey -Name 'vbawarnings' -Value 4 | Out-Null
        Set-CPReg -Path $okKey -Name 'blockcontentexecutionfrominternet' -Value 1 | Out-Null
    }

    # Best-effort hardware DEP (AlwaysOn)
    Invoke-CP 'enable hardware DEP (bcdedit AlwaysOn)' {
        $null = & bcdedit.exe /set "{current}" nx AlwaysOn 2>&1
    } | Out-Null

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

    # cmd/wmic/cscript restrictions are DANGEROUS on CP images -- the scoring
    # client and your own tooling use them. report, do not block.
    Add-Finding -Id 'REG-CMD-Block' -Area 'Registry' -Status 'INFO' -Detail 'cmd.exe / wmic / regedit restriction NOT applied' `
        -Hint 'If the README explicitly asks you to block script hosts, use AppLocker or SRP -- not a Deny ACE on cmd.exe. Denying cmd.exe locks you out of your own tooling.'
}
# ------------------------------------------------------------------------------
# network: firewall, smb, tcp/ip
# ------------------------------------------------------------------------------
function Invoke-Network {
    Write-Banner 'NETWORK / FIREWALL / SMB'
    if ($script:Para) { Write-CP 'paranoid mode: network pass skipped' 'warn'; return }

    Invoke-CP 'firewall profiles on, inbound blocked by default' {
        $netOk = $true
        try {
            Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True `
                -DefaultInboundAction Block -DefaultOutboundAction Allow `
                -LogBlocked True -LogIgnored False -NotifyOnListen True -ErrorAction Stop
        } catch { $netOk = $false }
        if (-not $netOk) {
            # Get-NetFirewallProfile missing on some old images
            foreach ($p in @('domainprofile','privateprofile','publicprofile')) {
                $null = & netsh advfirewall set $p state on 2>&1
                $null = & netsh advfirewall set $p firewallpolicy blockinbound,allowoutbound 2>&1
            }
        }
    }
    foreach ($p in @('Domain','Private','Public')) {
        try {
            $f = Get-NetFirewallProfile -Profile $p -ErrorAction Stop
            $good = $f.Enabled -and ($f.DefaultInboundAction -eq 'Block')
            Add-Finding -Id "FW-$p" -Area 'Firewall' -Status $(if ($good) {'PASS'} else {'FAIL'}) `
                -Detail "$p enabled=$($f.Enabled) defaultInbound=$($f.DefaultInboundAction)"
        } catch {
            $out = & netsh advfirewall show "$($p.ToLower())profile" state 2>&1
            Add-Finding -Id "FW-$p" -Area 'Firewall' -Status $(if ("$out" -match 'ON') {'PASS'} else {'FAIL'}) -Detail "$p state (netsh): $out"
        }
    }

    Invoke-CP 'firewall logging' {
        New-Item -ItemType Directory -Path (Join-Path $script:Root 'fwlogs') -Force -ErrorAction SilentlyContinue | Out-Null
        foreach ($p in @('Domain','Private','Public')) {
            Set-NetFirewallProfile -Profile $p -LogFileName (Join-Path $script:Root 'fwlogs\pfirewall.log') `
                -LogMaxSizeKilobytes 16384 -ErrorAction SilentlyContinue
        }
    }

    # wide-open inbound allow rules defeat the whole firewall. rules with no
    # display group are usually hand-made -- the sneaky ones live there.
    Invoke-CP 'permissive inbound rule scan' {
        $bad = New-Object System.Collections.Generic.List[object]
        try {
            $rules = @(Get-NetFirewallRule -ErrorAction Stop | Where-Object {
                $_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow'
            })
            foreach ($r in $rules) {
                $pf   = $r | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
                $addr = $r | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
                $anyPort  = (-not $pf)   -or (-not $pf.LocalPort) -or ($pf.LocalPort -eq 'Any')
                $anyProto = (-not $pf)   -or (-not $pf.Protocol)   -or ($pf.Protocol -eq 'Any')
                $anyAddr  = (-not $addr) -or ((@($addr.RemoteAddress) -join ',') -match 'Any')
                if ($anyPort -and $anyProto -and $anyAddr) {
                    $bad.Add([pscustomobject]@{ Name=$r.DisplayName; Profile=$r.Profile })
                }
            }
        } catch { Write-CP ("could not enumerate firewall rules: " + $_.Exception.Message) 'warn' }
        $bad | Export-Csv (Join-Path $script:EvDir 'firewall-permissive.csv') -NoTypeInformation
        if ($bad.Count -gt 0) {
            Add-Finding -Id 'FW-PERMISSIVE' -Area 'Firewall' -Status 'FAIL' -Detail "$($bad.Count) allow-ALL-inbound rule(s)" `
                -Hint 'An "allow all inbound" rule defeats the whole firewall. Delete it unless the README demands it.'
            foreach ($b in $bad) { Write-Host ("     - {0}" -f $b.Name) -ForegroundColor DarkYellow }
            if ($script:Agg -and (Confirm-CP "AGGRESSIVE: disable $($bad.Count) wide-open inbound allow rule(s)?")) {
                foreach ($b in $bad) {
                    Get-NetFirewallRule -DisplayName $b.Name -ErrorAction SilentlyContinue |
                        Disable-NetFirewallRule -ErrorAction SilentlyContinue
                }
                Register-Change -What 'Wide-open inbound firewall rules' -Old "$($bad.Count) enabled" -New 'disabled'
            }
        } else {
            Add-Finding -Id 'FW-PERMISSIVE' -Area 'Firewall' -Status 'PASS' -Detail 'no allow-all inbound rules'
        }
    }

    # Optional -Aggressive LOLBin outbound firewall block rules
    if ($script:Agg -and (Confirm-CP 'AGGRESSIVE: add outbound firewall block rules for common LOLBins (mshta/certutil/regsvr32/wscript/cscript/hh/cmstp/pcalua)?')) {
        Invoke-CP 'LOLBin outbound firewall rules' {
            $lolbins = @(
                "$env:windir\System32\mshta.exe",
                "$env:windir\System32\certutil.exe",
                "$env:windir\System32\regsvr32.exe",
                "$env:windir\System32\wscript.exe",
                "$env:windir\System32\cscript.exe",
                "$env:windir\hh.exe",
                "$env:windir\System32\cmstp.exe",
                "$env:windir\System32\pcalua.exe"
            )
            foreach ($lb in $lolbins) {
                if (-not (Test-Path $lb)) { continue }
                $rName = 'cbpt-Block-' + [IO.Path]::GetFileName($lb)
                if (-not (Get-NetFirewallRule -DisplayName $rName -ErrorAction SilentlyContinue)) {
                    New-NetFirewallRule -DisplayName $rName -Direction Outbound -Action Block `
                        -Program $lb -Profile Any -Enabled True -ErrorAction SilentlyContinue | Out-Null
                }
            }
            Add-Finding -Id 'FW-LOLBIN' -Area 'Firewall' -Status 'PASS' -Detail 'LOLBin outbound block rules applied'
        } | Out-Null
    }

    # non-default & hidden SMB share remediation
    Invoke-CP 'non-default SMB share remediation' {
        try {
            $customShares = @(Get-SmbShare -ErrorAction Stop | Where-Object {
                $_.Name -notmatch '^(ADMIN\$|IPC\$|print\$|SYSVOL|NETLOGON|[A-Z]\$)$'
            })
            foreach ($cs in $customShares) {
                Write-CP ("custom/hidden share found: '{0}' -> {1}" -f $cs.Name, $cs.Path) 'warn'
                if ($Force -or (Confirm-CP ("Remove SMB share '{0}' ({1})? Say NO if README requires file sharing." -f $cs.Name, $cs.Path))) {
                    Remove-SmbShare -Name $cs.Name -Force -ErrorAction Stop
                    Register-Change -What "SMB Share $($cs.Name)" -Old $cs.Path -New 'removed'
                    Add-Finding -Id "SHARE-REM-$($cs.Name)" -Area 'Shares' -Status 'PASS' -Detail "removed share $($cs.Name)"
                }
            }
        } catch {}
    }

    # SMBv1 & risky Windows Optional / Server Features
    Invoke-CP 'SMBv1 + risky Windows Optional Features disable' {
        $optFeats = @('SMB1Protocol','SimpleTCP','TelnetClient','TelnetServer','TFTP',
                      'MicrosoftWindowsPowerShellV2','MicrosoftWindowsPowerShellV2Root',
                      'WorkFolders-Client','Printing-LPDPrintService','Printing-LPRPortMonitor')
        foreach ($fn in $optFeats) {
            try {
                $f = Get-WindowsOptionalFeature -Online -FeatureName $fn -ErrorAction Stop
                if ($f -and $f.State -eq 'Enabled') {
                    Disable-WindowsOptionalFeature -Online -FeatureName $fn -NoRestart -ErrorAction SilentlyContinue | Out-Null
                    Register-Change -What "OptionalFeature $fn" -Old 'Enabled' -New 'Disabled'
                    Add-Finding -Id "FEAT-$fn" -Area 'Features' -Status 'PASS' -Detail "disabled feature $fn"
                }
            } catch {}
        }
        if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
            foreach ($sfn in @('Telnet-Client','TFTP-Client','SNMP-Service','FS-SMB1','Simple-TCPIP')) {
                try {
                    $sf = Get-WindowsFeature -Name $sfn -ErrorAction Stop
                    if ($sf -and $sf.Installed) {
                        Uninstall-WindowsFeature -Name $sfn -ErrorAction SilentlyContinue | Out-Null
                        Register-Change -What "ServerFeature $sfn" -Old 'Installed' -New 'Removed'
                    }
                } catch {}
            }
        }
        try { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop } catch {}
        Set-CPReg 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1' 0 | Out-Null
    }
    try {
        $f = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop
        Add-Finding -Id 'SMB-V1' -Area 'SMB' -Status $(if ($f.State -ne 'Enabled') {'PASS'} else {'FAIL'}) -Detail "SMB1Protocol = $($f.State)"
    } catch { Add-Finding -Id 'SMB-V1' -Area 'SMB' -Status 'PASS' -Detail 'SMBv1 disable attempted (query unavailable)' }

    Invoke-CP 'SMB signing enforcement' {
        try {
            Set-SmbServerConfiguration -RequireSecuritySignature $true -EnableSecuritySignature $true `
                -EnableInsecureGuestLogons $false -AutoDisconnect 15 -Force -ErrorAction Stop
            Add-Finding -Id 'SMB-SIGN' -Area 'SMB' -Status 'PASS' -Detail 'SMB signing required on server'
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
    if ($script:Agg) {
        Invoke-CP 'NetBIOS over TCP/IP off' {
            foreach ($a in @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction SilentlyContinue)) {
                $null = $a.SetTcpipNetbios(2)
            }
            Set-CPReg 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' 'NetbiosOptions' 2 | Out-Null
            Add-Finding -Id 'NET-NETBIOS' -Area 'Network' -Status 'PASS' -Detail 'NetBIOS over TCP/IP disabled on all adapters'
        } | Out-Null
        Invoke-CP 'admin shares off (C$ / ADMIN$)' {
            Set-CPReg 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'AutoShareWks'    0 -Id 'SMB-AdminShare' -Area 'SMB' | Out-Null
            Set-CPReg 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'AutoShareServer' 0 | Out-Null
        } | Out-Null
    } else {
        Add-Finding -Id 'NET-NETBIOS' -Area 'Network' -Status 'INFO' -Detail 'NetBIOS left as-is' `
            -Hint 'Run with -Aggressive to disable NetBIOS over TCP/IP. Check the README first if the box is a file server or a DC.'
    }

    Invoke-CP 'WinRM listener check' {
        $l = & winrm enumerate winrm/config/listener 2>&1
        if ("$l" -match 'Transport') {
            if ($script:Agg) {
                $null = & winrm delete 'winrm/config/listener?Address=*+Transport=HTTP' 2>&1
                Add-Finding -Id 'NET-WinRM' -Area 'Network' -Status 'PASS' -Detail 'HTTP WinRM listener removed'
            } else {
                Add-Finding -Id 'NET-WinRM' -Area 'Network' -Status 'WARN' -Detail 'WinRM HTTP listener present' `
                    -Hint 'HTTP WinRM (5985) is unencrypted. Remove it unless remote management is a stated critical service.'
            }
        }
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
    if ($script:Dry) {
        Add-Finding -Id "SVC-$n" -Area 'Services' -Status 'SKIP' -Detail "[dry-run] would stop + disable $n (was $before)"
        return
    }
    $ok = Invoke-CP "stop + disable service '$n' ($($svc.why))" {
        Stop-Service -Name $n -Force -ErrorAction SilentlyContinue
        if (-not (Set-CPStartType -Name $n -Type 'Disabled')) { throw 'could not set start type' }
    }
    $now = Get-CPService $n
    $nowState = if ($now) { "$($now.Status)/$(Get-CPStartType $n)" } else { 'missing' }
    if ($ok -and $now -and $now.Status -eq 'Stopped' -and (Get-CPStartType $n) -eq 'Disabled') {
        Add-Finding -Id "SVC-$n" -Area 'Services' -Status 'PASS' -Detail "$n disabled (was $before)"
        Register-Change -What "Service $n" -Old $before -New 'Stopped/Disabled'
    } else {
        Add-Finding -Id "SVC-$n" -Area 'Services' -Status 'WARN' -Detail "$n NOT fully disabled (now $nowState)" `
            -Hint "sc.exe stop $n ; sc.exe config $n start= disabled -- check dependencies and permissions."
    }
}

function Invoke-Services {
    Write-Banner 'SERVICES'
    if ($script:Para) { Write-CP 'paranoid mode: service pass skipped' 'warn'; return }

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
        @{n='RemoteAccess';       why='Routing and Remote Access'},
        @{n='SessionEnv';         why='Remote Desktop Configuration'},
        @{n='UmRdpService';       why='RDP UserMode Port Redirector'},
        @{n='HomeGroupListener';  why='legacy HomeGroup listener'},
        @{n='HomeGroupProvider';  why='legacy HomeGroup provider'},
        @{n='lltdsvc';            why='Link-Layer Topology Discovery'},
        @{n='p2pimsvc';           why='Peer Networking Identity Manager'},
        @{n='p2psvc';             why='Peer Networking Grouping'},
        @{n='PNRPsvc';            why='Peer Name Resolution Protocol'},
        @{n='iprip';              why='RIP Listener'},
        @{n='TapiSrv';            why='Telephony'},
        @{n='NetTcpPortSharing';  why='Net.Tcp Port Sharing'},
        @{n='RasAuto';            why='Remote Access Auto Connection Manager'},
        @{n='RasMan';             why='Remote Access Connection Manager'},
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

    $aggOff = @(
        @{n='FTPSVC';      why='IIS FTP server'},
        @{n='Msftpsvc';    why='legacy IIS FTP service'},
        @{n='WINS';        why='Windows Internet Name Service'},
        @{n='Spooler';     why='Print Spooler (disable if no printer needed)'},
        @{n='SNMP';        why='SNMP service'},
        @{n='SNMPTRAP';    why='SNMP trap'},
        @{n='WinRM';       why='Windows Remote Management'},
        @{n='TermService'; why='Remote Desktop Services'},
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
        @{n='UsoSvc';                st='Manual';    why='Update Orchestrator Service'},
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

    if ($script:Agg) {
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
        Add-Finding -Id 'SVC-AGG' -Area 'Services' -Status 'INFO' -Detail 'web/db/FTP/DNS/Spooler services left alone' `
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
        $good = ($m.st -eq 'Manual' -and $nt -eq 'Manual') -or ($now -and $now.Status -eq 'Running' -and $nt -eq $m.st)
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
    if ($script:Para) { Write-CP 'paranoid mode: defender pass skipped' 'warn'; return }

    Invoke-CP 'defender service re-enabled' {
        $s = Get-CPService 'WinDefend'
        if ($s -and (Get-CPStartType 'WinDefend') -eq 'Disabled') {
            [void](Set-CPStartType -Name 'WinDefend' -Type 'Automatic')
            Start-Service WinDefend -ErrorAction SilentlyContinue
        }
    }

    # a policy key can silently switch Defender off -- clear it first & enforce hygiene
    Invoke-CP 'clear Defender-disabling policies + enforce Defender policy hygiene' {
        $pk = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
        Remove-ItemProperty -Path $pk -Name 'DisableAntiSpyware' -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $pk -Name 'DisableAntiVirus'   -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path "$pk\Real-Time Protection" -Name 'DisableRealtimeMonitoring' -ErrorAction SilentlyContinue
        Set-CPReg -Path $pk -Name 'ServiceKeepAlive' -Value 1 | Out-Null
        Set-CPReg -Path "$pk\Scan" -Name 'CheckForSignaturesBeforeRunningScan' -Value 1 | Out-Null
        Set-CPReg -Path "$pk\Scan" -Name 'DisableHeuristics' -Value 0 | Out-Null
        Set-CPReg -Path "$pk\Real-Time Protection" -Name 'DisableIOAVProtection' -Value 0 | Out-Null
    }

    Invoke-CP 'defender preferences (realtime/behavior/PUA/MAPS)' {
        Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false `
            -DisableIOAVProtection $false -DisableScriptScanning $false -DisableArchiveScanning $false `
            -DisableRemovableDriveScanning $false -DisableEmailScanning $false `
            -MAPSReporting Advanced -SubmitSamplesConsent SendSafeSamples `
            -PUAProtection Enabled -ErrorAction Stop
    }

    # ASR rules -- the highest-value Defender block. worth trying even on
    # older platforms; unsupported IDs just no-op.
    Invoke-CP 'attack surface reduction rules + network protection' {
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
            'e6db77e5-3df2-4cf1-b95a-636979351e5b' = 1   # WMI persistence
        }
        $ids = New-Object System.Collections.Generic.List[string]
        $acts = New-Object System.Collections.Generic.List[int]
        foreach ($k in $asr.Keys) { $ids.Add($k); $acts.Add($asr[$k]) }
        Set-MpPreference -AttackSurfaceReductionRules_Ids $ids.ToArray() -AttackSurfaceReductionRules_Actions $acts.ToArray() -ErrorAction SilentlyContinue
        Set-MpPreference -EnableNetworkProtection Enabled -ErrorAction SilentlyContinue
        Set-MpPreference -EnableControlledFolderAccess Enabled -ErrorAction SilentlyContinue
    }

    # exclusions are where "disabled AV" hides on CP images
    Invoke-CP 'defender exclusion inventory' {
        $pref = Get-MpPreference -ErrorAction SilentlyContinue
        $rows = New-Object System.Collections.Generic.List[object]
        foreach ($x in @($pref.ExclusionPath))      { if ($x) { $rows.Add([pscustomobject]@{Type='Path';Value=$x}) } }
        foreach ($x in @($pref.ExclusionProcess))   { if ($x) { $rows.Add([pscustomobject]@{Type='Process';Value=$x}) } }
        foreach ($x in @($pref.ExclusionExtension)) { if ($x) { $rows.Add([pscustomobject]@{Type='Extension';Value=$x}) } }
        $rows | Export-Csv (Join-Path $script:EvDir 'defender-exclusions.csv') -NoTypeInformation
        if ($rows.Count -gt 0) {
            Add-Finding -Id 'DEF-EXCL' -Area 'Defender' -Status 'WARN' -Detail "$($rows.Count) Defender exclusion(s) inventoried" `
                -Hint 'An exclusion covering C:\ or *.exe is "AV turned off" with extra steps. Remove it unless the README justifies it: Remove-MpPreference -ExclusionPath <path>'
            if (-not ($script:Para -or $script:Dry)) {
                Write-Host ''
                $c = Read-Host '  remove ALL Defender exclusions? (y/N)'
                if ($c -match '^[Yy]') {
                    Invoke-CP 'remove Defender exclusions' {
                        foreach ($r in $rows) {
                            if ($r.Type -eq 'Path')      { Remove-MpPreference -ExclusionPath      $r.Value -ErrorAction SilentlyContinue }
                            if ($r.Type -eq 'Process')   { Remove-MpPreference -ExclusionProcess   $r.Value -ErrorAction SilentlyContinue }
                            if ($r.Type -eq 'Extension') { Remove-MpPreference -ExclusionExtension $r.Value -ErrorAction SilentlyContinue }
                        }
                    } | Out-Null
                }
            }
        } else {
            Add-Finding -Id 'DEF-EXCL' -Area 'Defender' -Status 'PASS' -Detail 'no Defender exclusions'
        }
    }

    Invoke-CP 'signature update attempt' {
        Update-MpSignature -ErrorAction Stop
        Add-Finding -Id 'DEF-SIG' -Area 'Defender' -Status 'PASS' -Detail 'signatures updated'
    }
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        Add-Finding -Id 'DEF-RT' -Area 'Defender' -Status $(if ($mp.RealTimeProtectionEnabled) {'PASS'} else {'FAIL'}) `
            -Detail "RealTimeProtection = $($mp.RealTimeProtectionEnabled)" `
            -Hint $(if ($mp.RealTimeProtectionEnabled) {''} else {'Tamper protection can block the change. Reboot and re-check, or fix via Windows Security UI.'})
    } catch {}

    # quick scan runs non-blocking in background job (unless -SkipScan) so it doesn't stall the clock
    Invoke-CP 'defender threat history + background quick scan' {
        if (-not $SkipScan) {
            try { Start-Job -ScriptBlock { Start-MpScan -ScanType QuickScan -ErrorAction SilentlyContinue } -ErrorAction SilentlyContinue | Out-Null } catch {}
            Write-CP 'Defender QuickScan launched in background job (use Get-Job to check)' 'info'
        } else {
            Write-CP 'QuickScan skipped (-SkipScan)' 'info'
        }
        $t = @(Get-MpThreatDetection -ErrorAction SilentlyContinue)
        $t | Export-Csv (Join-Path $script:EvDir 'defender-threats.csv') -NoTypeInformation
        if ($t.Count -gt 0) {
            Add-Finding -Id 'DEF-THREAT' -Area 'Defender' -Status 'FAIL' -Detail "$($t.Count) threat detection(s) in history" `
                -Hint 'Get-MpThreat | Format-List -- record threat name, resource path, detection time. This is very often a forensic answer.'
        } else {
            Add-Finding -Id 'DEF-THREAT' -Area 'Defender' -Status 'PASS' -Detail 'no recorded threats'
        }
    }

    Invoke-CP 'windows update service re-enabled' {
        [void](Set-CPStartType -Name 'wuauserv' -Type 'Automatic')
        Start-Service wuauserv -ErrorAction SilentlyContinue
        [void](Set-CPStartType -Name 'BITS' -Type 'Automatic')
        Start-Service BITS -ErrorAction SilentlyContinue
        $st = Get-CPStartType 'wuauserv'
        Add-Finding -Id 'WU-SVC' -Area 'Updates' -Status $(if ($st -ne 'Disabled') {'PASS'} else {'FAIL'}) -Detail "wuauserv = $st"
    }

    Invoke-CP 'event log sizing + retention' {
        foreach ($l in @('Security','System','Application')) {
            $null = & wevtutil sl $l /ms:134217728 /retention:true 2>&1
        }
        Add-Finding -Id 'LOG-SIZE' -Area 'Logging' -Status 'PASS' -Detail 'Security/System/Application logs = 128 MB, retention on'
    }

    Invoke-CP 'advanced audit policy (auditpol)' {
        # Ensure subcategory override is active alongside auditpol subcategories
        Set-CPReg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'SCENoApplyLegacyAuditPolicy' 1 | Out-Null
        $auditOk = $true
        foreach ($cat in @('System','Logon/Logoff','Object Access','Privilege Use','Detailed Tracking',
                           'Policy Change','Account Management','DS Access','Account Logon')) {
            $null = & auditpol /set /category:"$cat" /success:enable /failure:enable 2>&1
            if ($LASTEXITCODE -ne 0) { $auditOk = $false }
        }
        foreach ($sub in @('Process Creation','Logon','Special Logon','Other Logon/Logoff Events',
                           'Account Lockout','User Account Management','Security Group Management',
                           'Audit Policy Change','Sensitive Privilege Use','Removable Storage',
                           'File Share','Credential Validation','Other Account Logon Events')) {
            $null = & auditpol /set /subcategory:"$sub" /success:enable /failure:enable 2>&1
            if ($LASTEXITCODE -ne 0) { $auditOk = $false }
        }
        # include the command line in 4688 process-creation events. gold for forensics.
        Set-CPReg 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' `
            'ProcessCreationIncludeCmdLine_Enabled' 1 -Id 'AUD-CMDLINE' -Area 'Audit' | Out-Null
        $null = & auditpol /get /category:* 2>&1 | Set-Content (Join-Path $script:EvDir '81-auditpol.txt')
        if ($auditOk) {
            Add-Finding -Id 'AUD-ADV' -Area 'Audit' -Status 'PASS' -Detail 'audit subcategories on, process command line logging on'
        } else {
            Add-Finding -Id 'AUD-ADV' -Area 'Audit' -Status 'WARN' -Detail 'one or more auditpol categories failed' `
                -Hint 'Run auditpol /get /category:* and apply the failed subcategories by hand; a localized category name is the usual cause.'
        }
    }
}

# ------------------------------------------------------------------------------
# installed server apps: detect, harden config, NEVER touch their data
# ------------------------------------------------------------------------------
function Invoke-Apps {
    Write-Banner 'INSTALLED SERVICES / APPS'

    # ---- IIS -------------------------------------------------------------
    $iisSvc = Get-CPService 'W3SVC'
    if ($iisSvc -or (Test-Path C:\inetpub)) {
        Write-CP 'IIS detected' 'head'
        $ah = "$env:windir\System32\inetsrv\config\applicationHost.config"
        if (Test-Path $ah) { Backup-CPFile $ah }
        Invoke-CP 'IIS hardening (appcmd)' {
            $appcmd = "$env:windir\System32\inetsrv\appcmd.exe"
            if (-not (Test-Path $appcmd)) { throw 'appcmd.exe not found' }
            $null = & $appcmd set config /section:directoryBrowse /enabled:false /commit:apphost 2>&1
            $null = & $appcmd set config /section:httpErrors /errorMode:Custom /commit:apphost 2>&1
            foreach ($ext in @('.config','.cs','.csproj','.vb','.vbproj','.user','.webinfo','.licx','.resx',
                               '.resources','.mdb','.vbs','.java','.old','.bak','.orig','.save','.sql',
                               '.asa','.asax','.ashx','.asmx','.axd','.master','.sitemap','.ldf','.mdf')) {
                $null = & $appcmd set config -section:requestFiltering /+"fileExtensions.[fileExtension='$ext',allowed='False']" /commit:apphost 2>&1
            }
            foreach ($v in @('TRACE','TRACK','DEBUG','PROPFIND','PUT','DELETE')) {
                $null = & $appcmd set config -section:requestFiltering /+"verbs.[verb='$v',allowed='False']" /commit:apphost 2>&1
            }
            foreach ($seq in @('..','%','%252e','%c0%af','%255c')) {
                $null = & $appcmd set config -section:requestFiltering /+"denyUrlSequences.[sequence='$seq']" /commit:apphost 2>&1
            }
            $null = & $appcmd set config -section:requestFiltering /requestLimits.maxAllowedContentLength:"30000000" /commit:apphost 2>&1
            $null = & $appcmd set config -section:system.webServer/httpProtocol /+"customHeaders.[name='X-Content-Type-Options',value='nosniff']" /commit:apphost 2>&1
            $null = & $appcmd set config -section:system.webServer/httpProtocol /+"customHeaders.[name='X-Frame-Options',value='SAMEORIGIN']" /commit:apphost 2>&1
            Add-Finding -Id 'APP-IIS' -Area 'Apps' -Status 'PASS' -Detail 'IIS: dir browse off, request filtering, verbs blocked, security headers'
        }
        $ah = "$env:windir\System32\inetsrv\config\applicationHost.config"
        if (Test-Path $ah) {
            Backup-CPFile $ah
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
        Invoke-CP ("harden httpd.conf: " + $conf.FullName) {
            Backup-CPFile $conf.FullName
            $c = Get-Content $conf.FullName -Raw
            $orig = $c
            $c = $c -replace '(?m)^\s*ServerTokens\s+.*$',   'ServerTokens Prod'
            $c = $c -replace '(?m)^\s*ServerSignature\s+.*$', 'ServerSignature Off'
            $c = $c -replace '(?m)^\s*TraceEnable\s+.*$',     'TraceEnable Off'
            if ($c -notmatch '(?m)^\s*ServerTokens') {
                $c += "`r`n# hardening (cbptwindows)`r`nServerTokens Prod`r`nServerSignature Off`r`nTraceEnable Off`r`n"
            }
            $c = $c -replace 'Options\s+(?:All\s+)?Indexes', 'Options -Indexes'
            if ($c -ne $orig) { Set-Content -Path $conf.FullName -Value $c -Encoding ASCII }
        }
        Add-Finding -Id 'APP-APACHE-DIRS' -Area 'Apps' -Status 'INFO' -Detail 'manual Apache checks required' `
            -Hint 'Look for "Options Indexes FollowSymLinks", "Require all granted" on a filesystem root, TLSv1/1.1 in SSLProtocol. Restart Apache after every change and confirm it still listens.'
        Invoke-CP 'restart apache' {
            $svc = @(Get-Service 'Apache2.4','Apache2.2','Apache' -ErrorAction SilentlyContinue | Select-Object -First 1)
            if ($svc) { Restart-Service $svc.Name -Force -ErrorAction Stop }
        } | Out-Null
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
                Backup-CPFile $ini.FullName
                $c = Get-Content $ini.FullName -Raw
                if ($c -notmatch '(?m)^\s*(skip-networking|bind-address)') {
                    Add-Content $ini.FullName "`r`n# hardening (cbptwindows)`r`nbind-address=127.0.0.1`r`nskip-symbolic-links=1`r`nlocal-infile=0`r`n"
                    Add-Finding -Id 'APP-MYSQL' -Area 'Apps' -Status 'PASS' -Detail 'my.ini: bind 127.0.0.1, local-infile off'
                } else {
                    Add-Finding -Id 'APP-MYSQL' -Area 'Apps' -Status 'PASS' -Detail 'my.ini already binds or disables networking'
                }
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
            if ($b -and (Get-CPStartType 'SQLBrowser') -ne 'Disabled') {
                Stop-Service SQLBrowser -Force -ErrorAction SilentlyContinue
                [void](Set-CPStartType -Name 'SQLBrowser' -Type 'Disabled')
                Add-Finding -Id 'APP-MSSQL-BROWSER' -Area 'Apps' -Status 'PASS' -Detail 'SQL Browser disabled'
            }
        }
        Add-Finding -Id 'APP-MSSQL' -Area 'Apps' -Status 'INFO' -Detail 'SQL Server present, manual checks required' `
            -Hint 'Disable/rename sa + strong password; Windows-only auth unless the README requires mixed mode; remove BUILTIN\Users login; confirm SQL Browser is off.'
    }

    # ---- Windows OpenSSH Server ---------------------------------------------
    $sshCfg = Join-Path $env:ProgramData 'ssh\sshd_config'
    if ((Get-CPService 'sshd') -or (Test-Path $sshCfg)) {
        Write-CP 'Windows OpenSSH Server detected' 'head'
        if ((Test-Path $sshCfg) -and -not ($script:Para -or $script:Dry)) {
            Invoke-CP 'harden Windows sshd_config' {
                Backup-CPFile $sshCfg
                $bak = "$sshCfg.cbptbak"
                Copy-Item -LiteralPath $sshCfg -Destination $bak -Force
                $lines = New-Object System.Collections.Generic.List[string]
                foreach ($ln in (Get-Content -LiteralPath $sshCfg -ErrorAction Stop)) { $lines.Add($ln) }
                $opts = [ordered]@{
                    'PermitRootLogin'        = 'no'
                    'PermitEmptyPasswords'   = 'no'
                    'MaxAuthTries'           = '3'
                    'X11Forwarding'          = 'no'
                    'AllowAgentForwarding'   = 'no'
                    'AllowTcpForwarding'     = 'no'
                    'ClientAliveInterval'    = '300'
                    'ClientAliveCountMax'    = '2'
                    'LoginGraceTime'         = '60'
                    'UseDNS'                 = 'no'
                }
                foreach ($k in $opts.Keys) {
                    $set = $false
                    for ($i = 0; $i -lt $lines.Count; $i++) {
                        if ($lines[$i] -match ("^\s*#?\s*{0}\b" -f [regex]::Escape($k))) {
                            if (-not $set) { $lines[$i] = "$k $($opts[$k])"; $set = $true }
                        }
                    }
                    if (-not $set) { $lines.Add("$k $($opts[$k])") }
                }
                Set-Content -LiteralPath $sshCfg -Value $lines -Encoding ASCII
                $sshdExe = @(Get-Command sshd.exe -ErrorAction SilentlyContinue | Select-Object -First 1).Source
                if (-not $sshdExe -and (Test-Path "$env:windir\System32\OpenSSH\sshd.exe")) { $sshdExe = "$env:windir\System32\OpenSSH\sshd.exe" }
                if ($sshdExe) {
                    $null = & $sshdExe -t -f $sshCfg 2>&1
                    if ($LASTEXITCODE -ne 0) {
                        Copy-Item -LiteralPath $bak -Destination $sshCfg -Force
                        Remove-Item -LiteralPath $bak -Force -ErrorAction SilentlyContinue
                        throw 'sshd.exe -t validation failed; rolled back sshd_config'
                    }
                }
                Remove-Item -LiteralPath $bak -Force -ErrorAction SilentlyContinue
                $ssvc = Get-CPService 'sshd'
                if ($ssvc -and $ssvc.Status -eq 'Running') { Restart-Service sshd -Force -ErrorAction SilentlyContinue }
                Add-Finding -Id 'APP-OPENSSH' -Area 'Apps' -Status 'PASS' -Detail 'Windows OpenSSH sshd_config hardened + validated'
            } | Out-Null
        } else {
            Add-Finding -Id 'APP-OPENSSH' -Area 'Apps' -Status 'INFO' -Detail "OpenSSH config at $sshCfg (dry-run/paranoid or missing)"
        }
    }
}

# ------------------------------------------------------------------------------
# software audit / outdated apps / interactive uninstall helper
# ------------------------------------------------------------------------------
function Invoke-Software {
    Write-Banner 'SOFTWARE AUDIT & UPDATES'

    $paths = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
               'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
               'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*')
    $p = @(Get-ItemProperty $paths -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName })
    $suspect = '(?i)teamviewer|ammyy|anydesk|logmein|vnc|tightvnc|realvnc|ultravnc|tigervnc|radmin|rustdesk|parsec|ngrok|hamachi|zerotier|nmap|zenmap|wireshark|fiddler|charles|winpcap|npcap|mimikatz|rubeus|sharphound|bloodhound|netcat|ncat|putty|filezilla|winscp|cyberduck|tftp|torrent|utorrent|bittorrent|qbittorrent|deluge|transmission|frostwire|vuze|xmrig|minergate|keylog|procexp|procmon|process hacker|nirsoft|pwdump|fgdump|quarks|psexec|hydra|john|hashcat|ophcrack|cain|abel|angry ip|angryip|advanced ip|advanced port|metasploit|burp|nessus|aircrack|sqlmap|nikto|gobuster|dirb|ettercap|bettercap|ghidra|x64dbg|ollydbg|cheat engine|autohotkey|wildtangent|windirstat|ccleaner|bonjour|tor browser|openvpn|emule|skype|discord|steam|epic games|battle\.net|riot|roblox|minecraft|origin|ea app|uplay|gog galaxy'
    $hits = @($p | Where-Object { $_.DisplayName -match $suspect })
    foreach ($x in $hits) {
        Add-Finding -Id "SW-$($x.DisplayName)" -Area 'Software' -Status 'WARN' `
            -Detail "suspect software: $($x.DisplayName) ($($x.DisplayVersion))" `
            -Hint 'Check README; uninstall if unauthorized.'
        if (-not ($script:Para -or $script:Dry)) {
            $uStr = "$($x.QuietUninstallString)"
            if (-not $uStr) { $uStr = "$($x.UninstallString)" }
            if ($uStr -and -not $Force) {
                $ans = Read-Host "  uninstall '$($x.DisplayName)'? (y/N)"
                if ($ans -match '^[Yy]') {
                    Invoke-CP "uninstall '$($x.DisplayName)'" {
                        if ($uStr -match 'msiexec(\.exe)?\s+.*[/{]([0-9A-Fa-f-]+)[}]?') {
                            $guid = $Matches[2]
                            Start-Process msiexec.exe -ArgumentList "/x {$guid} /qn /norestart" -Wait -NoNewWindow
                        } elseif ($uStr -match '^"([^"]+)"\s*(.*)$') {
                            $exe = $Matches[1]; $arg = $Matches[2]
                            Start-Process -FilePath $exe -ArgumentList $arg -Wait -NoNewWindow
                        } else {
                            Start-Process cmd.exe -ArgumentList "/c $uStr" -Wait -NoNewWindow
                        }
                        Register-Change -What "Software:$($x.DisplayName)" -Old "$($x.DisplayVersion)" -New 'uninstall invoked'
                    } | Out-Null
                }
            }
        }
    }

    # Store / Appx bloatware & games
    try {
        $appx = @(Get-AppxPackage -AllUsers -ErrorAction Stop | Where-Object {
            $_.Name -match '(?i)candycrush|solitaire|xboxgaming|wildtangent|minecraft|roblox|disney|tiktok|spotify|torrent'
        })
        foreach ($ax in $appx) {
            Add-Finding -Id "SW-APPX-$($ax.Name)" -Area 'Software' -Status 'WARN' -Detail "Store app: $($ax.Name) ($($ax.Version))"
            if (-not ($script:Para -or $script:Dry -or $Force)) {
                $ans = Read-Host "  remove Store app '$($ax.Name)' for all users? (y/N)"
                if ($ans -match '^[Yy]') {
                    Invoke-CP "remove Appx '$($ax.Name)'" {
                        Remove-AppxPackage -Package $ax.PackageFullName -AllUsers -ErrorAction SilentlyContinue
                        Register-Change -What "Appx:$($ax.Name)" -Old $ax.Version -New 'removed'
                    } | Out-Null
                }
            }
        }
    } catch {}

    # winget outdated third-party app updates (e.g. Notepad++, browsers, 7-Zip)
    if (Get-Command winget.exe -ErrorAction SilentlyContinue) {
        Write-CP 'checking winget available upgrades...' 'step'
        try {
            $wgOut = & winget.exe upgrade --accept-source-agreements 2>&1
            $wgOut | Set-Content (Join-Path $script:EvDir '72-winget-upgrade.txt')
            $wgOut | Select-Object -First 40 | ForEach-Object { Write-Host ("   " + $_) }
            if (-not ($script:Para -or $script:Dry -or $Force)) {
                $uAns = Read-Host '  run winget upgrade --all for outdated apps? (y/N)'
                if ($uAns -match '^[Yy]') {
                    Invoke-CP 'winget upgrade --all' {
                        & winget.exe upgrade --all --accept-source-agreements --accept-package-agreements --silent
                    } | Out-Null
                }
            }
        } catch {}
    } else {
        Add-Finding -Id 'SW-WINGET' -Area 'Software' -Status 'INFO' -Detail 'winget not installed -- update Notepad++/browsers/7-Zip manually'
    }
}

# ------------------------------------------------------------------------------
# file inventory (media / password files / user executables / archives). NOTHING deleted.
# ------------------------------------------------------------------------------
function Invoke-Files {
    Write-Banner 'FILE INVENTORY (no deletes)'

    $mediaRx = '(?i)\.(mp3|mp4|m4a|avi|mkv|mov|wmv|flac|wav|ogg|aac|wma|webm|torrent|pcap|pcapng)$'
    $exeRx   = '(?i)\.(exe|msi|bat|cmd|ps1|vbs|scr|js|jar)$'
    $archRx  = '(?i)(\.(zip|rar|7z|tar\.gz|tgz)|(?:^|[\\/._-])(nc|nc64|ncat|netcat|pyrdp|windirstat|wildtangent|wireshark|nmap|mimikatz|xprobe|doona)(?:[\\/._-]|$))'
    $docRx   = '(?i)\.(txt|csv|xlsx|docx|rtf|md)$'
    $credRx  = '(?i)pass|cred|secret|hack|crack|keylog|login'

    $rows = New-Object System.Collections.Generic.List[object]
    $exe  = New-Object System.Collections.Generic.List[object]
    $docs = New-Object System.Collections.Generic.List[object]
    $arch = New-Object System.Collections.Generic.List[object]

    $roots = New-Object System.Collections.Generic.List[string]
    foreach ($p in (Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue)) {
        if ($p.Name -in @('Default','Default User','All Users')) { continue }
        $roots.Add($p.FullName)
    }
    foreach ($extra in @('C:\Temp','C:\Downloads')) {
        if (Test-Path $extra) { $roots.Add($extra) }
    }

    foreach ($r in $roots) {
        foreach ($f in (Get-ChildItem $r -Recurse -File -ErrorAction SilentlyContinue)) {
            $fn = $f.FullName
            if ($fn -match '(?i)\\AppData\\') { continue }
            if ($f.Name -match $mediaRx) {
                $rows.Add([pscustomobject]@{ FullName=$fn; Length=$f.Length; LastWriteTime=$f.LastWriteTime })
            }
            if ($f.Name -match $exeRx -and $fn -match '(?i)\\(Desktop|Downloads|Documents|Public|Temp)\\') {
                $exe.Add([pscustomobject]@{ FullName=$fn; Length=$f.Length; LastWriteTime=$f.LastWriteTime })
            }
            if ($f.Name -match $docRx -and $f.Name -match $credRx) {
                $docs.Add([pscustomobject]@{ FullName=$fn; Length=$f.Length })
            }
            if ($f.Name -match $archRx) {
                $arch.Add([pscustomobject]@{ FullName=$fn; Length=$f.Length; LastWriteTime=$f.LastWriteTime })
            }
        }
    }

    $rows | Export-Csv (Join-Path $script:EvDir 'media-files.csv') -NoTypeInformation
    if ($rows.Count -gt 0) {
        Add-Finding -Id 'FILES-MEDIA' -Area 'Files' -Status 'WARN' -Detail "$($rows.Count) media/prohibited-type file(s) inventoried" `
            -Hint 'Delete ONLY what the README calls prohibited (usually a media/p2p policy). Games and movies in user folders are usually points.'
    } else {
        Add-Finding -Id 'FILES-MEDIA' -Area 'Files' -Status 'PASS' -Detail 'no media files in user profiles'
    }

    $exe | Export-Csv (Join-Path $script:EvDir 'user-executables.csv') -NoTypeInformation
    if ($exe.Count -gt 0) {
        Add-Finding -Id 'FILES-EXE' -Area 'Files' -Status 'WARN' -Detail "$($exe.Count) executable(s)/script(s) in user/public/temp folders" `
            -Hint 'Check each against the README and the forensic questions before deleting. Unexplained exes are usually malware.'
    } else {
        Add-Finding -Id 'FILES-EXE' -Area 'Files' -Status 'PASS' -Detail 'no executables in user folders'
    }

    $docs | Export-Csv (Join-Path $script:EvDir 'suspect-documents.csv') -NoTypeInformation
    if ($docs.Count -gt 0) {
        Add-Finding -Id 'FILES-DOCS' -Area 'Files' -Status 'WARN' -Detail "$($docs.Count) password/credential-named document(s)" `
            -Hint 'Password lists are usually a scored policy violation. Record the path in the report; deleting business data loses points.'
    } else {
        Add-Finding -Id 'FILES-DOCS' -Area 'Files' -Status 'PASS' -Detail 'no password-named documents in user profiles'
    }

    $arch | Export-Csv (Join-Path $script:EvDir 'prohibited-archives-tools.csv') -NoTypeInformation
    if ($arch.Count -gt 0) {
        Add-Finding -Id 'FILES-ARCHIVES' -Area 'Files' -Status 'WARN' -Detail "$($arch.Count) archive/tool drop(s) (zip/7z/nc/pyrdp/wireshark/etc.)" `
            -Hint 'Review prohibited-archives-tools.csv -- CyberPatriot images hide prohibited software archives (e.g. pyrdp, nc, netcat) in Downloads/Public/Temp.'
    } else {
        Add-Finding -Id 'FILES-ARCHIVES' -Area 'Files' -Status 'PASS' -Detail 'no prohibited archives or tool drops found'
    }
    Write-CP "full inventory -> $script:EvDir" 'ok'
}
# ------------------------------------------------------------------------------
# verify / scorecard
# ------------------------------------------------------------------------------
function Invoke-Verify {
    Write-Banner 'VERIFY'

    # ---- secedit re-export -------------------------------------------------
    Invoke-CP 'secedit re-export + policy checks' {
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
            # DS Access only exists on domain controllers; a workstation export
            # legitimately omits it. do not report a false FAIL.
            if ($a -eq 'AuditDSAccess' -and $v -lt 0) { continue }
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
        @{p='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; n='LimitBlankPasswordUse'; want='1'; id='VER-BlankPw'},
        @{p='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; n='DisableDomainCreds'; want='1'; id='VER-DisableDomainCreds'},
        @{p='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; n='SCENoApplyLegacyAuditPolicy'; want='1'; id='VER-NoLegacyAudit'},
        @{p='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; n='RunAsPPL'; want='1'; id='VER-RunAsPPL'},
        @{p='HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\WDigest'; n='UseLogonCredential'; want='0'; id='VER-WDigest'},
        @{p='HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'; n='UseLogonCredential'; want='0'; id='VER-WDigestReal'},
        @{p='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; n='DontDisplayLastUserName'; want='1'; id='VER-LastUser'},
        @{p='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI'; n='EnumerateAdministrators'; want='0'; id='VER-EnumAdmins'},
        @{p='HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; n='EnableSmartScreen'; want='1'; id='VER-SmartScreen'},
        @{p='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer'; n='SmartScreenEnabled'; want='RequireAdmin'; id='VER-SmartScreenExp'},
        @{p='HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance'; n='fAllowToGetHelp'; want='0'; id='VER-RemoteAssist'},
        @{p='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'; n='NoAutoUpdate'; want='0'; id='VER-WUAuto'},
        @{p='HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; n='RequireSecuritySignature'; want='1'; id='VER-SMBSign'},
        @{p='HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'; n='RequireSecuritySignature'; want='1'; id='VER-SMBSignC'},
        @{p='HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'; n='DisableIPSourceRouting'; want='2'; id='VER-IPSrcRoute'},
        @{p='HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'; n='EnableICMPRedirect'; want='0'; id='VER-ICMPRedirect'},
        @{p='HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'; n='SynAttackProtect'; want='1'; id='VER-SynProtect'},
        @{p='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; n='Hidden'; want='1'; id='VER-ShowHidden'},
        @{p='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; n='HideFileExt'; want='0'; id='VER-ShowExt'},
        @{p='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; n='NoDriveTypeAutoRun'; want='255'; id='VER-Autorun'},
        @{p='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; n='EnableScriptBlockLogging'; want='1'; id='VER-PSLog'},
        @{p='HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'; n='UserAuthentication'; want='1'; id='VER-NLA'}
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

    # ---- live auditpol subcategories ---------------------------------------
    foreach ($sub in @('Credential Validation','Logon','Account Lockout','User Account Management','Process Creation','Audit Policy Change')) {
        $ao = (& auditpol /get /subcategory:"$sub" 2>&1) -join ' '
        $hasBoth = ($ao -match 'Success and Failure')
        Add-Finding -Id ("VER-AUD-" + ($sub -replace '\s+','')) -Area 'Verify' -Status $(if ($hasBoth) {'PASS'} else {'WARN'}) `
            -Detail "auditpol [$sub]: $(if ($hasBoth) {'Success and Failure'} else {'not Success and Failure'})"
    }

    # ---- custom/hidden SMB shares & User Rights ----------------------------
    try {
        $badShares = @(Get-SmbShare -ErrorAction Stop | Where-Object {
            $_.Name -notmatch '^(ADMIN\$|IPC\$|print\$|SYSVOL|NETLOGON|[A-Z]\$)$'
        })
        Add-Finding -Id 'VER-SHARES-CUSTOM' -Area 'Verify' -Status $(if ($badShares.Count -eq 0) {'PASS'} else {'FAIL'}) `
            -Detail "$(if ($badShares.Count -eq 0) {'no custom/hidden SMB shares'} else {"custom/hidden shares remain: $(($badShares | ForEach-Object {$_.Name}) -join ', ')"})"
    } catch {}

    try {
        $urList = Get-CPUserRights
        $admNames = @(Get-AdminMemberNames)
        $badU = New-Object System.Collections.Generic.List[string]
        foreach ($ur in $urList) {
            if ($ur.Right -notin @('SeSecurityPrivilege','SeTakeOwnershipPrivilege','SeDebugPrivilege','SeTcbPrivilege','SeBackupPrivilege','SeRestorePrivilege','SeLoadDriverPrivilege','SeManageVolumePrivilege','SeRemoteShutdownPrivilege','SeCreateTokenPrivilege','SeRelabelPrivilege','SeTrustedCredManAccessPrivilege','SeEnableDelegationPrivilege')) { continue }
            foreach ($nm in $ur.Names) {
                $short = ($nm -split '\\')[-1]
                if ($short -match '^(Administrators|SYSTEM)$') { continue }
                if ($short -match '^(Everyone|Anonymous Logon|ANONYMOUS LOGON|Guest|Guests|Users|Authenticated Users)$' -or ($admNames -notcontains $short)) {
                    $badU.Add("$($ur.Right)=$nm")
                }
            }
        }
        Add-Finding -Id 'VER-URIGHTS' -Area 'Verify' -Status $(if ($badU.Count -eq 0) {'PASS'} else {'FAIL'}) `
            -Detail "$(if ($badU.Count -eq 0) {'sensitive User Rights Assignments clean'} else {"unauthorized privileges: $($badU -join '; ')"})"
    } catch {}

    # ---- optional features -------------------------------------------------
    foreach ($fn in @('SimpleTCP','TelnetClient','TFTP','SMB1Protocol')) {
        try {
            $feat = Get-WindowsOptionalFeature -Online -FeatureName $fn -ErrorAction Stop
            Add-Finding -Id "VER-FEAT-$fn" -Area 'Verify' -Status $(if ($feat.State -ne 'Enabled') {'PASS'} else {'FAIL'}) -Detail "$fn = $($feat.State)"
        } catch {}
    }

    # autologon: an absent key is also a PASS
    $al = Get-CPReg -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'AutoAdminLogon'
    Add-Finding -Id 'VER-AutoLogon' -Area 'Verify' -Status $(if ($null -eq $al -or "$al" -eq '0') {'PASS'} else {'FAIL'}) `
        -Detail "AutoAdminLogon=$al"

    # ---- guest + hidden + RID500 ----------------------------------------------
    $g = @(Get-CPUsers) | Where-Object { $_.SID -match '-501$' } | Select-Object -First 1
    if ($g) { Add-Finding -Id 'VER-GUEST' -Area 'Verify' -Status $(if (-not $g.Enabled) {'PASS'} else {'FAIL'}) -Detail "guest enabled = $($g.Enabled)" }
    $r5 = @(Get-CPUsers) | Where-Object { $_.SID -match '-500$' -and $_.Name -ne 'Administrator' } | Select-Object -First 1
    if ($r5) { Add-Finding -Id 'VER-RID500' -Area 'Verify' -Status 'FAIL' -Detail "RID-500 clone account: $($r5.Name)" `
        -Hint 'A cloned admin. Deal with it in the users section and report it.' }

    # ---- defender ------------------------------------------------------------
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        Add-Finding -Id 'VER-DEF-RT' -Area 'Verify' -Status $(if ($mp.RealTimeProtectionEnabled) {'PASS'} else {'FAIL'}) -Detail "RealTimeProtection = $($mp.RealTimeProtectionEnabled)"
        Add-Finding -Id 'VER-DEF-AV' -Area 'Verify' -Status $(if ($mp.AntivirusEnabled) {'PASS'} else {'FAIL'}) -Detail "AntivirusEnabled = $($mp.AntivirusEnabled)"
        $pref = Get-MpPreference -ErrorAction Stop
        Add-Finding -Id 'VER-DEF-PUA' -Area 'Verify' -Status $(if ($pref.PUAProtection -ne 0) {'PASS'} else {'FAIL'}) -Detail "PUAProtection = $($pref.PUAProtection)"
    } catch {}

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
    } catch {}

    # ---- wuauserv ------------------------------------------------------------------
    $st = Get-CPStartType 'wuauserv'
    Add-Finding -Id 'VER-WU' -Area 'Verify' -Status $(if ($st -ne 'Disabled') {'PASS'} else {'FAIL'}) -Detail "wuauserv = $st"

    # ---- reboot needed? --------------------------------------------------------------
    $reboot = @()
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $reboot += 'CBS pending' }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $reboot += 'Windows Update required' }
    if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations') { $reboot += 'pending file rename' }
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
   TLS cipher order, WDigest off, LSA PPL. all of these are one registry
   key each and they add up.

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
# interactive menu
# ------------------------------------------------------------------------------
function Show-Menu {
    while ($true) {
        Write-Banner ("cbptwindows $script:Version  --  $script:Hostname")
        $tags = ''
        if ($script:Agg)  { $tags += ' [AGGRESSIVE]' }
        if ($script:Para) { $tags += ' [PARANOID]' }
        if ($script:Dry)  { $tags += ' [DRY RUN]' }
        if ($tags) { Write-Host ("   mode:{0}" -f $tags) -ForegroundColor Yellow }
        Write-Host ''
        Write-Host '   r) recon + evidence dump      (read only, safe)'  -ForegroundColor White
        Write-Host '   b) backup only'                                    -ForegroundColor White
        Write-Host '   1) users + local security policy (users.txt/admins.txt/groups.txt + secedit)' -ForegroundColor White
        Write-Host '   2) registry hardening (LSA/UAC/SMB/TLS/SmartScreen/WU/PS logging)' -ForegroundColor White
        Write-Host '   3) network / firewall / SMB / optional features'   -ForegroundColor White
        Write-Host '   4) services'                                       -ForegroundColor White
        Write-Host '   5) defender + audit + updates'                     -ForegroundColor White
        Write-Host '   6) installed apps (IIS/Apache/MySQL/OpenSSH)'      -ForegroundColor White
        Write-Host '   7) file inventory (media/PII/exes/archives, no deletes)' -ForegroundColor White
        Write-Host '   8) software audit / updates / uninstall helper'    -ForegroundColor White
        Write-Host '   v) verify + scorecard'                              -ForegroundColor White
        Write-Host '   a) RUN ALL (backup -> recon -> harden -> verify)'  -ForegroundColor Green
        Write-Host '   h) hints: how to max the score'                     -ForegroundColor Cyan
        Write-Host ("   x) toggle -Aggressive   (currently: {0})" -f $script:Agg)  -ForegroundColor $(if($script:Agg){'Yellow'}else{'White'})
        Write-Host ("   p) toggle -Paranoid     (currently: {0})" -f $script:Para) -ForegroundColor $(if($script:Para){'Yellow'}else{'White'})
        Write-Host ("   d) toggle -DryRun       (currently: {0})" -f $script:Dry)  -ForegroundColor $(if($script:Dry){'Yellow'}else{'White'})
        Write-Host '   q) quit'                                               -ForegroundColor DarkGray
        Write-Host ''
        $c = ''
        try { $c = (Read-Host '  pick one').Trim().ToLower() } catch { return }
        switch -Regex ($c) {
            '^r' { Invoke-Recon;       Export-Report }
            '^b' { New-CPBackup -ForceBackup }
            '^1' { Invoke-Users;       Export-Report }
            '^2' { if (-not ($script:Para -or $NoBackup -or $script:Dry)) { New-CPBackup }; Invoke-Registry;    Export-Report }
            '^3' { if (-not ($script:Para -or $NoBackup -or $script:Dry)) { New-CPBackup }; Invoke-Network;     Export-Report }
            '^4' { if (-not ($script:Para -or $NoBackup -or $script:Dry)) { New-CPBackup }; Invoke-Services;    Export-Report }
            '^5' { if (-not ($script:Para -or $NoBackup -or $script:Dry)) { New-CPBackup }; Invoke-Defender;    Export-Report }
            '^6' { if (-not ($script:Para -or $NoBackup -or $script:Dry)) { New-CPBackup }; Invoke-Apps;        Export-Report }
            '^7' { if (-not ($script:Para -or $NoBackup -or $script:Dry)) { New-CPBackup }; Invoke-Files;       Export-Report }
            '^8' { if (-not ($script:Para -or $NoBackup -or $script:Dry)) { New-CPBackup }; Invoke-Software;    Export-Report }
            '^v' { Invoke-Verify;      Export-Report }
            '^a' {
                if (Confirm-CP 'Run the full safe pass now? (backup, recon, users, registry, network, services, defender, apps, software, files, verify)') {
                    New-CPBackup
                    Invoke-Recon
                    Invoke-Users
                    Invoke-Registry
                    Invoke-Network
                    Invoke-Services
                    Invoke-Defender
                    Invoke-Apps
                    Invoke-Software
                    Invoke-Files
                    Invoke-Verify
                    Export-Report
                }
            }
            '^h' { Show-Hints }
            '^x' { $script:Agg  = -not $script:Agg }
            '^p' { $script:Para = -not $script:Para }
            '^d' { $script:Dry  = -not $script:Dry }
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
    New-Item -ItemType Directory -Path $script:Root -Force -ErrorAction SilentlyContinue | Out-Null
    New-Item -ItemType Directory -Path $script:EvDir -Force -ErrorAction SilentlyContinue | Out-Null
    New-Item -ItemType Directory -Path $script:BkDir -Force -ErrorAction SilentlyContinue | Out-Null
    if (Test-Path $script:ReviewFile) { Remove-Item $script:ReviewFile -Force -ErrorAction SilentlyContinue }
    try { Start-Transcript -Path (Join-Path $script:Root ("transcript-" + $script:Stamp + ".txt")) -Force -ErrorAction SilentlyContinue | Out-Null } catch {}

    Write-Banner ("cbptwindows $script:Version   |   $script:Hostname   |   " + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
    $tier = 'DEFAULT (safe)'
    if ($script:Para)    { $tier = 'PARANOID (read only)' }
    elseif ($script:Agg) { $tier = 'AGGRESSIVE' }
    Write-CP ("tier: {0}{1}" -f $tier, $(if ($Force) { ' [non-interactive]' } else { '' })) 'head'
    if ($script:Dry) { Write-CP 'dry-run: nothing on the system will change' 'warn' }

    # -Hints is pure documentation, it does not need elevation
    if ($Hints) { Show-Hints; try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch {}; return }

    if (-not (Test-Admin)) {
        Write-CP 'you are not running elevated. right-click PowerShell -> Run as administrator.' 'err'
        Write-CP 'most of this silently fails otherwise. -Hints works without elevation.' 'err'
        if (-not $Force) { try { Read-Host 'press enter to exit' | Out-Null } catch {} }
        try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch {}
        exit 1
    }

    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    if ($os) { Write-CP ("{0} ({1}) -- installed {2}" -f $os.Caption, $os.Version, $os.InstallDate) 'info' }
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        Write-CP 'PowerShell < 5.1 detected. Get-LocalUser / Get-SmbShare fall back or get skipped.' 'warn'
    }

    if ($Restore) { Restore-CPBackup -Path $Restore; try { Stop-Transcript -ErrorAction SilentlyContinue | Out-Null } catch {}; return }

    # single-section runs change policy/registry/firewall/services too; take a
    # backup first unless the operator explicitly asked for none.
    $backupPhases = @('registry','network','services','defender','apps','software','files')
    if (($backupPhases -contains $Phase) -and -not ($script:Para -or $NoBackup -or $script:Dry)) {
        New-CPBackup
    }

    switch ($Phase) {
        'menu'     { Show-Menu }
        'recon'    { if (-not ($script:Para -or $NoBackup -or $script:Dry)) { New-CPBackup }; Invoke-Recon; Export-Report }
        'users'    { if (-not ($script:Para -or $NoBackup -or $script:Dry)) { New-CPBackup }; Invoke-Users; Export-Report }
        'registry' { Invoke-Registry; Export-Report }
        'network'  { Invoke-Network; Export-Report }
        'services' { Invoke-Services; Export-Report }
        'defender' { Invoke-Defender; Export-Report }
        'apps'     { Invoke-Apps; Export-Report }
        'software' { Invoke-Software; Export-Report }
        'files'    { Invoke-Files; Export-Report }
        'verify'   { Invoke-Verify; Export-Report }
        'report'   { Export-Report }
        'guide'    { Show-Hints }
        'all'      {
            if (-not ($script:Para -or $NoBackup -or $script:Dry)) { New-CPBackup }
            Invoke-Recon
            Invoke-Users
            Invoke-Registry
            Invoke-Network
            Invoke-Services
            Invoke-Defender
            Invoke-Apps
            Invoke-Software
            Invoke-Files
            Invoke-Verify
            Export-Report
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
