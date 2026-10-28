<#
  Checks this Windows PC for indicators of the pine63 / claud-tips fake-"Claude"
  infostealer campaign (the Windows equivalent of mac-stealer-check.sh).

  Run from any PowerShell window:
      powershell -ExecutionPolicy Bypass -File win-stealer-check.ps1

  Prints a clear verdict. Exit code: 0 = no indicators found, 1 = indicators found.
  No admin rights required; checks that need elevation are skipped gracefully.
#>

$found = $false

function Pass($msg)  { Write-Host "  [OK]    " -ForegroundColor Green -NoNewline; Write-Host $msg }
function Fail($msg)  { Write-Host "  [FOUND] " -ForegroundColor Red   -NoNewline; Write-Host $msg; $script:found = $true }
function Detail($t)  { $t -split "`n" | ForEach-Object { if ($_.Trim()) { Write-Host ("            " + $_.Substring(0, [Math]::Min($_.Length,150))) } } }

# --- Indicators of Compromise for this campaign -------------------------------
# Network IOCs (attacker infrastructure seen in the Mac incident).
$iocPattern = 'pine63|claud-tips|206\.189\.104\.97'
# The "paste this to install" pattern: encoded PowerShell, or a download piped to iex.
$cmdPattern = '-enc\b|-encodedcommand|-e\s+[A-Za-z0-9+/=]{24,}|FromBase64String|' +
              '(iwr|irm|curl|wget|invoke-webrequest|invoke-restmethod)[^\r\n]*\|[^\r\n]*iex|' +
              'iex\s*\(\s*(iwr|irm|new-object|\[|\$)'
$suspect = "(?i)($iocPattern|$cmdPattern)"

Write-Host "`nChecking for stealer indicators...`n" -ForegroundColor White

# 1. Command history: PowerShell console history + the Win+R "Run" box (RunMRU).
#    The fake install flow has the victim paste a command into Run or a terminal.
$hist = @()
$psHist = Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
if (Test-Path $psHist) {
    $hist += Select-String -Path $psHist -Pattern $suspect -ErrorAction SilentlyContinue |
             Where-Object { $_.Line -notmatch 'win-stealer-check|Select-String' } |
             ForEach-Object { "history: $($_.Line)" }
}
try {
    $runMru = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU' -ErrorAction Stop
    $runMru.PSObject.Properties |
        Where-Object { $_.Name -match '^[a-z]$' -and $_.Value -match $suspect } |
        ForEach-Object { $hist += "Run box: $($_.Value)" }
} catch {}
if ($hist.Count -gt 0) {
    Fail "Suspicious install/download command in history:"
    Detail ($hist -join "`n")
} else {
    Pass "Command history (PowerShell + Run box): no encoded/pipe-to-iex or IOC command"
}

# 2. Persistence: Run / RunOnce keys, Startup folders, Scheduled Tasks.
#    Legit autostarts don't run encoded PowerShell or call attacker domains.
$persist = @()
$runKeys = @(
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
  'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
  'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
)
foreach ($k in $runKeys) {
    try {
        $p = Get-ItemProperty $k -ErrorAction Stop
        $p.PSObject.Properties |
            Where-Object { $_.Name -notmatch '^PS' -and $_.Value -match $suspect } |
            ForEach-Object { $persist += "$k -> $($_.Name) = $($_.Value)" }
    } catch {}
}
$startupDirs = @(
  (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup'),
  (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup')
)
foreach ($d in $startupDirs) {
    if (Test-Path $d) {
        Get-ChildItem $d -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '\.(ps1|vbs|js|bat|cmd|lnk|hta)$' } |
            ForEach-Object {
                $txt = try { Get-Content $_.FullName -Raw -ErrorAction Stop } catch { '' }
                if ($_.Name -match $suspect -or $txt -match $suspect) { $persist += "startup: $($_.FullName)" }
            }
    }
}
try {
    Get-ScheduledTask -ErrorAction Stop | ForEach-Object {
        foreach ($a in $_.Actions) {
            $line = "$($a.Execute) $($a.Arguments)"
            if ($line -match $suspect) { $persist += "task: \$($_.TaskPath)$($_.TaskName) -> $line" }
        }
    }
} catch {}
if ($persist.Count -gt 0) {
    Fail "Autostart/persistence running an encoded command or calling attacker infrastructure:"
    Detail ($persist -join "`n")
} else {
    Pass "Persistence (Run keys, Startup folders, Scheduled Tasks): nothing suspicious"
}

# 3. Dropped payload: files/folders in user-writable dirs that match the IOCs.
#    Windows stealers stage in %APPDATA% / %LOCALAPPDATA% / %TEMP% / %PROGRAMDATA%.
$dropHits = @()
$scanRoots = @($env:APPDATA, $env:LOCALAPPDATA, $env:TEMP, $env:ProgramData) | Select-Object -Unique
foreach ($r in $scanRoots) {
    if (Test-Path $r) {
        Get-ChildItem $r -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match "(?i)($iocPattern)" } |
            ForEach-Object { $dropHits += $_.FullName }
    }
}
# Hosts file pinning an attacker domain is another drop indicator.
$hosts = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
if (Test-Path $hosts) {
    Select-String -Path $hosts -Pattern "(?i)($iocPattern)" -ErrorAction SilentlyContinue |
        ForEach-Object { $dropHits += "hosts: $($_.Line.Trim())" }
}
if ($dropHits.Count -gt 0) {
    Fail "File, folder or hosts entry matching attacker infrastructure:"
    Detail ($dropHits -join "`n")
} else {
    Pass "User folders + hosts file: no pine63 / claud-tips / attacker-IP artifacts"
}

# --- Verdict ------------------------------------------------------------------
$line = '=============================================='
Write-Host ""
if ($found) {
    Write-Host $line -ForegroundColor Red
    Write-Host "  RESULT: INDICATORS FOUND - treat this PC as"  -ForegroundColor Red
    Write-Host "  compromised. Cut ALL internet now: Wi-Fi off," -ForegroundColor Red
    Write-Host "  no phone hotspot, unplug any network cable."   -ForegroundColor Red
    Write-Host "  Keep it switched on. Screenshot this and"      -ForegroundColor Red
    Write-Host "  send it privately to Maarten."                 -ForegroundColor Red
    Write-Host $line -ForegroundColor Red
    exit 1
} else {
    Write-Host $line -ForegroundColor Green
    Write-Host "  RESULT: NOT FOUND - no indicators of this"     -ForegroundColor Green
    Write-Host "  stealer on this PC."                           -ForegroundColor Green
    Write-Host $line -ForegroundColor Green
    exit 0
}
