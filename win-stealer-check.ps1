<#
  Checks this Windows PC for indicators of the pine63 / claud-tips fake-"Claude"
  infostealer campaign (the Windows equivalent of mac-stealer-check.sh).

  Run from any PowerShell window:
      powershell -ExecutionPolicy Bypass -File win-stealer-check.ps1

  Read-only; no admin rights required (checks that need elevation are skipped).
  Exit code: 0 = no indicators of this stealer, 1 = indicators found.

  Verdict tiers:
    INDICATORS FOUND (red)  = this campaign's infrastructure or malicious
                              persistence is present. Treat as compromised.
    REVIEW (yellow)         = install-style download commands were in history.
                              Legitimate installers look like this too; not this
                              stealer. Just confirm you recognise them.
    NOT FOUND (green)       = clean.
#>

$found  = $false   # hard indicators of THIS campaign
$review = @()       # install-style commands worth an eyeball, not alarming

function Pass($msg)   { Write-Host "  [OK]     " -ForegroundColor Green  -NoNewline; Write-Host $msg }
function Fail($msg)   { Write-Host "  [FOUND]  " -ForegroundColor Red    -NoNewline; Write-Host $msg; $script:found = $true }
function Note($msg)   { Write-Host "  [REVIEW] " -ForegroundColor Yellow -NoNewline; Write-Host $msg }
function Detail($t)   { $t -split "`n" | ForEach-Object { if ($_.Trim()) { Write-Host ("            " + $_.Substring(0, [Math]::Min($_.Length,150))) } } }

# --- Indicators of Compromise for this campaign -------------------------------
# High-confidence: attacker infrastructure seen in the incident.
$ioc   = 'pine63|claud-tips|206\.189\.104\.97'
# High-confidence: encoded / obfuscated command execution.
$enc   = '-enc\b|-encodedcommand|FromBase64String|-e\s+[A-Za-z0-9+/=]{24,}'
# Weak signal on its own: a download piped straight into execution.
$dl    = '(iwr|irm|curl|wget|invoke-webrequest|invoke-restmethod)[^\r\n]*\|[^\r\n]*iex|iex\s*\(\s*(iwr|irm|new-object)'
# Known-good installer domains that legitimately use the download-to-iex shape.
$allow = 'claude\.ai|anthropic\.com|astral\.sh|waimakers\.dev|github\.com|githubusercontent\.com|' +
         'microsoft\.com|powershellgallery\.com|chocolatey\.org|scoop\.sh|get\.scoop\.sh|python\.org|nodejs\.org|npmjs\.com'

# Classify one command line: 'bad' (campaign/encoded), 'review' (unknown download-to-iex), or '' (ignore).
function Classify($line) {
    if ($line -match "(?i)($ioc)")  { return 'bad' }
    if ($line -match "(?i)($enc)")  { return 'bad' }
    if ($line -match "(?i)($dl)" -and $line -notmatch "(?i)($allow)") { return 'review' }
    return ''
}

Write-Host "`nChecking for stealer indicators...`n" -ForegroundColor White

# 1. Command history: PowerShell history + the Win+R "Run" box (RunMRU).
$cmdLines = @()
$psHist = Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
if (Test-Path $psHist) {
    $cmdLines += Get-Content $psHist -ErrorAction SilentlyContinue |
                 Where-Object { $_ -notmatch 'win-stealer-check' }
}
try {
    $runMru = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU' -ErrorAction Stop
    $cmdLines += $runMru.PSObject.Properties | Where-Object { $_.Name -match '^[a-z]$' } | ForEach-Object { $_.Value }
} catch {}

$histBad = @(); $histReview = @()
foreach ($l in $cmdLines) {
    switch (Classify $l) {
        'bad'    { $histBad    += $l }
        'review' { $histReview += $l }
    }
}
if ($histBad.Count -gt 0) {
    Fail "Campaign IOC or encoded command in history:"
    Detail ($histBad -join "`n")
} elseif ($histReview.Count -gt 0) {
    Note "Install-style download commands in history (confirm you recognise these):"
    Detail ($histReview -join "`n")
    $review += $histReview
} else {
    Pass "Command history (PowerShell + Run box): clean"
}

# 2. Persistence: Run / RunOnce keys, Startup folders, Scheduled Tasks.
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
        (Get-ItemProperty $k -ErrorAction Stop).PSObject.Properties |
            Where-Object { $_.Name -notmatch '^PS' -and (Classify $_.Value) } |
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
                if ((Classify $_.Name) -or (Classify $txt)) { $persist += "startup: $($_.FullName)" }
            }
    }
}
try {
    Get-ScheduledTask -ErrorAction Stop | ForEach-Object {
        $tp = $_.TaskPath; $tn = $_.TaskName
        foreach ($a in $_.Actions) {
            $line = "$($a.Execute) $($a.Arguments)"
            if (Classify $line) { $persist += "task: $tp$tn -> $line" }
        }
    }
} catch {}
if ($persist.Count -gt 0) {
    Fail "Autostart/persistence running an encoded command or calling attacker infrastructure:"
    Detail ($persist -join "`n")
} else {
    Pass "Persistence (Run keys, Startup folders, Scheduled Tasks): nothing suspicious"
}

# 3. Dropped payload: files/folders or hosts entries matching the IOCs.
$dropHits = @()
$scanRoots = @($env:APPDATA, $env:LOCALAPPDATA, $env:TEMP, $env:ProgramData) | Select-Object -Unique
foreach ($r in $scanRoots) {
    if (Test-Path $r) {
        Get-ChildItem $r -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match "(?i)($ioc)" } |
            ForEach-Object { $dropHits += $_.FullName }
    }
}
$hosts = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
if (Test-Path $hosts) {
    Select-String -Path $hosts -Pattern "(?i)($ioc)" -ErrorAction SilentlyContinue |
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
} elseif ($review.Count -gt 0) {
    Write-Host $line -ForegroundColor Yellow
    Write-Host "  RESULT: NOT FOUND - no sign of this stealer."  -ForegroundColor Green
    Write-Host "  Note: install-style download commands were in" -ForegroundColor Yellow
    Write-Host "  your history (listed above). That is normal if" -ForegroundColor Yellow
    Write-Host "  you installed a tool that way; just confirm you" -ForegroundColor Yellow
    Write-Host "  recognise each one. No action needed otherwise." -ForegroundColor Yellow
    Write-Host $line -ForegroundColor Yellow
    exit 0
} else {
    Write-Host $line -ForegroundColor Green
    Write-Host "  RESULT: NOT FOUND - no indicators of this"     -ForegroundColor Green
    Write-Host "  stealer on this PC."                           -ForegroundColor Green
    Write-Host $line -ForegroundColor Green
    exit 0
}
