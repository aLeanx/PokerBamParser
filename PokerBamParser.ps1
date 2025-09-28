<#
Poker Bam Parser - Advanced Forensic Script
Special pentru verificări pe FiveM / RAGEMP.
Autor: ChatGPT & User
#>

param(
    [switch]$UseParallel,
    [string]$ExportCsv = "",
    [string]$ExportJson = "",
    [string]$ExportHtml = "$env:TEMP\PokerBamParser_Report.html",
    [string]$ConfigFile = ".\bam_config.json",
    [string]$LogFile = "$env:TEMP\PokerBamParser.log",
    [switch]$VerboseOutput
)

# ===== Logger =====
function Write-Log {
    param($Message, [string]$Level = "INFO")
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $line = "$ts [$Level] $Message"
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
    if ($VerboseOutput) { Write-Host $line }
}

# ===== Admin Check =====
function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}
if (-not (Test-Admin)) {
    Write-Warning "Please run this script as Administrator."
    exit 1
}

Write-Log "Started Poker Bam Parser"

# ===== Default Config =====
$KnownGtaExeNames = @("FiveM.exe","ragemp.exe","gta5.exe","FiveM_GTAProcess.exe")
$KnownGtaPathsPatterns = @("FiveM","ragemp","CitizenFX")

if (Test-Path $ConfigFile) {
    try {
        $cfg = Get-Content $ConfigFile -Raw | ConvertFrom-Json
        if ($cfg.ExeNames) { $KnownGtaExeNames = $cfg.ExeNames }
        if ($cfg.PathPatterns) { $KnownGtaPathsPatterns = $cfg.PathPatterns }
        Write-Log "Loaded config from $ConfigFile"
    } catch {
        Write-Warning "Invalid config file, using defaults."
    }
}

# ===== Signature Cache =====
$SigCache = @{}
function Get-Signature-Cached {
    param([string]$FilePath)
    if (-not (Test-Path $FilePath -PathType Leaf)) {
        return [PSCustomObject]@{ Status="FileNotFound"; Publisher=$null }
    }
    if ($SigCache.ContainsKey($FilePath)) { return $SigCache[$FilePath] }
    try {
        $sig = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction Stop
        $obj = [PSCustomObject]@{
            Status   = $sig.Status.ToString()
            Publisher= if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { $null }
        }
    } catch { $obj = [PSCustomObject]@{ Status="UnknownError"; Publisher=$null } }
    $SigCache[$FilePath] = $obj
    return $obj
}
function Get-FileHash-Safe($FilePath) {
    try { return (Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction Stop).Hash }
    catch { return $null }
}

# ===== Risk Score =====
function Get-RiskScore {
    param($entry)
    $score = 0
    if ($entry.SignatureStatus -ne "Valid") { $score += 2 }
    if (-not $entry.SHA256) { $score += 1 }
    if ($entry.LikelyGTAProcess) { $score += 2 }
    if ($entry.ProcessRunning) { $score += 1 }
    return $score
}

# ===== BAM Reading =====
$rpath = @(
 "HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings",
 "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
)
$Users = @()
foreach ($p in $rpath) {
    if (Test-Path $p) {
        $Users += Get-ChildItem -Path $p -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PSChildName
    }
}
$Users = $Users | Sort-Object -Unique

$allResults = @()
foreach ($sid in $Users) {
    foreach ($rp in $rpath) {
        $regUserPath = "$rp\$sid"
        if (-not (Test-Path $regUserPath)) { continue }
        $props = (Get-Item $regUserPath).Property
        $UserName = try {
            (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value
        } catch { $sid }

        foreach ($Item in $props) {
            $raw = (Get-ItemProperty $regUserPath).$Item
            if (-not $raw -or $raw.Length -lt 8) { continue }
            try {
                $ticks = [BitConverter]::ToInt64($raw,0)
                $dtUtc = [DateTime]::FromFileTimeUtc($ticks)
            } catch { continue }

            $f = Split-Path -Leaf $Item
            $sig = Get-Signature-Cached $Item
            $sha = Get-FileHash-Safe $Item
            $isGta = ($KnownGtaExeNames -contains $f) -or ($KnownGtaPathsPatterns | ForEach-Object { $Item -match $_ })
            $procRunning = try { (Get-Process -Name ([IO.Path]::GetFileNameWithoutExtension($f)) -ErrorAction SilentlyContinue) } catch { $null }
            $procRunning = [bool]$procRunning

            $obj = [PSCustomObject]@{
                Application = $f
                Path        = $Item
                User        = $UserName
                "Last Execution (UTC)" = $dtUtc.ToString("yyyy-MM-dd HH:mm:ss")
                SignatureStatus = $sig.Status
                Publisher   = $sig.Publisher
                SHA256      = $sha
                LikelyGTAProcess = $isGta
                ProcessRunning   = $procRunning
            }
            $obj | Add-Member -NotePropertyName RiskScore -NotePropertyValue (Get-RiskScore $obj)
            $allResults += $obj
        }
    }
}

# ===== Rezumat rapid =====
Write-Host "`n=== QUICK SUMMARY ===" -ForegroundColor Cyan
$allResults | Sort-Object "Last Execution (UTC)" -Descending | Select-Object -First 10 Application,Path,"Last Execution (UTC)",SignatureStatus,RiskScore | Format-Table -AutoSize

$runningSuspects = $allResults | Where-Object { $_.LikelyGTAProcess -and $_.ProcessRunning }
if ($runningSuspects) {
    Write-Host "`n⚠️  Suspect processes running:" -ForegroundColor Red
    $runningSuspects | Select-Object Application,Path,User,SignatureStatus | Format-Table -AutoSize
}

# ===== Export =====
if ($ExportCsv) { $allResults | Export-Csv $ExportCsv -NoTypeInformation -Force }
if ($ExportJson) { $allResults | ConvertTo-Json -Depth 5 | Set-Content $ExportJson -Force }
if ($ExportHtml) {
    $rows = foreach ($r in $allResults) {
        $cls = if ($r.SignatureStatus -eq "Valid") { "style='color:lime;'" }
               elseif ($r.SignatureStatus -eq "NotSigned") { "style='color:red;'" }
               else { "style='color:orange;'" }
        "<tr><td>$($r.Application)</td><td>$($r.Path)</td><td>$($r.User)</td><td>$($r.'Last Execution (UTC)')</td><td $cls>$($r.SignatureStatus)</td><td>$($r.RiskScore)</td></tr>"
    }
    $html = @"
<html><head><style>
body{background:#121212;color:#eee;font-family:Arial;}
table{border-collapse:collapse;width:100%;}
th,td{border:1px solid #444;padding:5px;}
th{background:#333;}
</style></head><body>
<h2>Poker Bam Parser Report</h2>
<table>
<tr><th>Application</th><th>Path</th><th>User</th><th>Last Execution (UTC)</th><th>Signature</th><th>Risk</th></tr>
$($rows -join "`n")
</table></body></html>
"@
    Set-Content -Path $ExportHtml -Value $html -Force
    Write-Host "`n📄 HTML report: $ExportHtml" -ForegroundColor Green
}
