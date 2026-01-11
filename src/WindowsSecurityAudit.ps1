#ADMIN CHECK
$adminCheck = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $adminCheck) {
    Write-Host "Please run this script as Administrator." -ForegroundColor Red
    exit
}
#PATH SETUP
$BasePath   = Split-Path -Parent $MyInvocation.MyCommand.Path
$ReportPath = Join-Path $BasePath "..\reports\audit_report.txt"

#START REPORT 
"================ WINDOWS SECURITY AUDIT REPORT ================" | Out-File $ReportPath
"Audit Date: $(Get-Date)" | Out-File $ReportPath -Append
"" | Out-File $ReportPath -Append

#OS INFORMATION (WMI)
$os = Get-WmiObject Win32_OperatingSystem
"Operating System: $($os.Caption)" | Out-File $ReportPath -Append
"Version: $($os.Version)" | Out-File $ReportPath -Append
"" | Out-File $ReportPath -Append

#ANTIVIRUS STATUS (WMI) 
"--- Antivirus Status (WMI) ---" | Out-File $ReportPath -Append
try {
    $av = Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct -ErrorAction Stop
    if ($av) {
        foreach ($product in $av) {
            "Antivirus Installed: $($product.displayName)" | Out-File $ReportPath -Append
        }
    } else {
        "WARNING: No Antivirus Detected" | Out-File $ReportPath -Append
    }
} catch {
    "ERROR: Unable to retrieve Antivirus information" | Out-File $ReportPath -Append
}
"" | Out-File $ReportPath -Append

#WINDOWS DEFENDER SERVICE (WMI) 
"--- Windows Defender Service ---" | Out-File $ReportPath -Append
$defender = Get-WmiObject Win32_Service | Where-Object { $_.Name -eq "WinDefend" }

if ($defender) {
    "Service Status: $($defender.State)" | Out-File $ReportPath -Append
    "Startup Type : $($defender.StartMode)" | Out-File $ReportPath -Append
} else {
    "Windows Defender Service Not Found" | Out-File $ReportPath -Append
}
"" | Out-File $ReportPath -Append
