$ErrorActionPreference = "SilentlyContinue"

function Get-Signature {

    [CmdletBinding()]
     param (
        [string[]]$FilePath
    )

    $Existence = Test-Path -PathType "Leaf" -Path $FilePath
    $Authenticode = (Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction SilentlyContinue).Status
    $Signature = "Invalid Signature (UnknownError)"

    if ($Existence) {
        if ($Authenticode -eq "Valid") {
            $Signature = "Valid Signature"
        }
        elseif ($Authenticode -eq "NotSigned") {
            $Signature = "Invalid Signature (NotSigned)"
        }
        elseif ($Authenticode -eq "HashMismatch") {
            $Signature = "Invalid Signature (HashMismatch)"
        }
        elseif ($Authenticode -eq "NotTrusted") {
            $Signature = "Invalid Signature (NotTrusted)"
        }
        elseif ($Authenticode -eq "UnknownError") {
            $Signature = "Invalid Signature (UnknownError)"
        }
        return $Signature
    } else {
        $Signature = "File Was Not Found"
        return $Signature
    }
}

Clear-Host

# ===================== BANNER =====================
Clear-Host

Write-Host "__________       __                  __________                  __________                                   " -ForegroundColor Cyan
Write-Host "\______   \____ |  | __ ___________  \______   \_____    _____   \______   \_____ _______  ______ ___________ " -ForegroundColor Cyan
Write-Host " |     ___/  _ \|  |/ // __ \_  __ \  |    |  _/\__  \  /     \   |     ___/\__  \\_  __ \/  ___// __ \_  __ \" -ForegroundColor Cyan
Write-Host " |    |  (  <_> )    <\  ___/|  | \/  |    |   \ / __ \|  Y Y  \  |    |     / __ \|  | \/\___ \\  ___/|  | \/" -ForegroundColor Cyan
Write-Host " |____|   \____/|__|_ \\___  >__|     |______  /(____  /__|_|  /  |____|    (____  /__|  /____  >\___  >__|   " -ForegroundColor Cyan
Write-Host "                     \/    \/                \/      \/      \/                  \/           \/     \/        " -ForegroundColor Cyan
Write-Host ""
Write-Host "                        Poker Bam Parser" -ForegroundColor Magenta
Write-Host ""


# ===================== CHECK ADMIN =====================
function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if (!(Test-Admin)) {
    Write-Warning "Please Run This Script as Admin."
    Start-Sleep 10
    Exit
}

# ===================== START TIMER =====================
$sw = [Diagnostics.Stopwatch]::StartNew()

if (!(Get-PSDrive -Name HKLM -PSProvider Registry)) {
    Try{ New-PSDrive -Name HKLM -PSProvider Registry -Root HKEY_LOCAL_MACHINE }
    Catch{ Write-Warning "Error Mounting HKEY_Local_Machine" }
}

$bv = ("bam", "bam\State")
Try {
    $Users = foreach($ii in $bv) {
        Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($ii)\UserSettings\" | Select-Object -ExpandProperty PSChildName
    }
} Catch {
    Write-Warning "Error Parsing BAM Key. Likely unsupported Windows Version"
    Exit
}

$rpath = @("HKLM:\SYSTEM\CurrentControlSet\Services\bam\","HKLM:\SYSTEM\CurrentControlSet\Services\bam\state\")

$UserTime = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation").TimeZoneKeyName
$UserBias = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation").ActiveTimeBias
$UserDay = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation").DaylightBias

# ===================== PARSE BAM DATA =====================
$Bam = Foreach ($Sid in $Users) {
    foreach($rp in $rpath){
        $BamItems = Get-Item -Path "$($rp)UserSettings\$Sid" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Property
        Write-Host -ForegroundColor Yellow "Extracting " -NoNewLine
        Write-Host -ForegroundColor Green "$($rp)UserSettings\$SID"

        Try {
            $objSID = New-Object System.Security.Principal.SecurityIdentifier($Sid)
            $User = $objSID.Translate([System.Security.Principal.NTAccount]).Value
        } Catch { $User="" }

        ForEach ($Item in $BamItems) {
            $Key = Get-ItemProperty -Path "$($rp)UserSettings\$Sid" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $Item

            If($Key.length -eq 24) {
                $Hex = [System.BitConverter]::ToString($Key[7..0]) -replace "-",""
                $TimeLocal = Get-Date ([DateTime]::FromFileTime([Convert]::ToInt64($Hex, 16))) -Format "yyyy-MM-dd HH:mm:ss"
                $TimeUTC = Get-Date ([DateTime]::FromFileTimeUtc([Convert]::ToInt64($Hex, 16))) -Format "yyyy-MM-dd HH:mm:ss"
                $Bias = -([convert]::ToInt32([Convert]::ToString($UserBias,2),2))
                $Day = -([convert]::ToInt32([Convert]::ToString($UserDay,2),2))
                $TimeUser = (Get-Date ([DateTime]::FromFileTimeUtc([Convert]::ToInt64($Hex, 16))).AddMinutes($Bias) -Format "yyyy-MM-dd HH:mm:ss")
                $f = Split-Path -Leaf $Item
                $sig = Get-Signature -FilePath $Item

                [PSCustomObject]@{
                    'Examiner Time' = $TimeLocal
                    'Last Execution Time (UTC)'= $TimeUTC
                    'Last Execution User Time' = $TimeUser
                    Application = $f
                    Path = $Item
                    Signature = $sig
                    User = $User
                    SID = $Sid
                    Regpath = $rp
                }
            }
        }
    }
}

# ===================== OUTPUT =====================
$Bam | Out-GridView -PassThru -Title "Poker Bam Parser - BAM entries $($Bam.count)  - User TimeZone: ($UserTime) -> ActiveBias: ( $Bias) - DayLightTime: ($Day)"

$sw.Stop()
$t = $sw.Elapsed.TotalMinutes
Write-Host ""
Write-Host "Elapsed Time $t Minutes" -ForegroundColor Yellow

