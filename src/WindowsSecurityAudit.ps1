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

# ---------------- FIREWALL STATUS (WMI) ----------------
"--- Firewall Status ---" | Out-File $ReportPath -Append
try {
    $firewall = Get-WmiObject -Namespace root\StandardCimv2 -Class MSFT_NetFirewallProfile
    foreach ($profile in $firewall) {
        "Profile: $($profile.Name) | Enabled: $($profile.Enabled)" | Out-File $ReportPath -Append
    }
} catch {
    "Unable to retrieve Firewall status via WMI" | Out-File $ReportPath -Append
}
"" | Out-File $ReportPath -Append
# ---------------- UAC STATUS (REGISTRY VIA WMI) ----------------
"--- User Account Control (UAC) ---" | Out-File $ReportPath -Append
$regUAC = Get-WmiObject -Class StdRegProv -Namespace root\default

if ($regUAC) {
    $EnableLUA = 0
    $regUAC.GetDWORDValue(
        2147483650,
        "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "EnableLUA",
        [ref]$EnableLUA
    )

    if ($EnableLUA -eq 1) {
        "UAC Status: Enabled (Secure)" | Out-File $ReportPath -Append
    } else {
        "UAC Status: Disabled (HIGH RISK)" | Out-File $ReportPath -Append
    }
} else {
    "Unable to read UAC registry values" | Out-File $ReportPath -Append
}
"" | Out-File $ReportPath -Append

# ---------------- PASSWORD POLICY (SAFE METHOD) ----------------
"--- Password Policy ---" | Out-File $ReportPath -Append
net accounts | Out-File $ReportPath -Append
"" | Out-File $ReportPath -Append
# ---------------- REMOTE DESKTOP STATUS (REGISTRY VIA WMI) ----------------
"--- Remote Desktop ---" | Out-File $ReportPath -Append
$regRDP = Get-WmiObject -Class StdRegProv -Namespace root\default

if ($regRDP) {
    $RDPValue = 1
    $regRDP.GetDWORDValue(
        2147483650,
        "SYSTEM\CurrentControlSet\Control\Terminal Server",
        "fDenyTSConnections",
        [ref]$RDPValue
    )

    if ($RDPValue -eq 0) {
        "Remote Desktop: Enabled (RISK)" | Out-File $ReportPath -Append
    } else {
        "Remote Desktop: Disabled (Secure)" | Out-File $ReportPath -Append
    }
} else {
    "Unable to read Remote Desktop registry settings" | Out-File $ReportPath -Append
}
"" | Out-File $ReportPath -Append
# ---------------- ADMIN USERS (WMI) ----------------
"--- Administrator Accounts ---" | Out-File $ReportPath -Append
$admins = Get-WmiObject Win32_GroupUser |
    Where-Object { $_.GroupComponent -like "*Administrators*" }

foreach ($admin in $admins) {
    $admin.PartComponent | Out-File $ReportPath -Append
}
"" | Out-File $ReportPath -Append

# ---------------- AUDIT COMPLETE ----------------
"================ AUDIT COMPLETED =================" | Out-File $ReportPath -Append

Write-Host "Audit completed successfully." -ForegroundColor Green
Write-Host "Report saved at: $ReportPath"

