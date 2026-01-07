#ADMIN CHECK
$adminCheck = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $adminCheck) {
    Write-Host "Please run this script as Administrator." -ForegroundColor Red
    exit
}