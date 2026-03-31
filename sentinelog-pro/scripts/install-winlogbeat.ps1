# ══════════════════════════════════════════════════════════════════════
#  SentineLog PRO — Installation Winlogbeat (machine cliente Windows)
#  Lance en PowerShell Administrator sur CHAQUE machine à surveiller
#  Usage: .\install-winlogbeat.ps1 -SiemIP "192.168.1.100"
# ══════════════════════════════════════════════════════════════════════

param(
    [Parameter(Mandatory=$true)]
    [string]$SiemIP,
    [string]$WinlogbeatVersion = "8.12.0",
    [string]$InstallPath = "C:\Program Files\winlogbeat"
)

$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"

function Write-OK   { param($m) Write-Host "  ✓ $m" -ForegroundColor Green }
function Write-Step { param($m) Write-Host "  → $m" -ForegroundColor White }
function Write-Warn { param($m) Write-Host "  ⚠ $m" -ForegroundColor Yellow }

Write-Host "`n══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  SentineLog — Installation Winlogbeat" -ForegroundColor Cyan
Write-Host "  SIEM Server: $SiemIP" -ForegroundColor Cyan
Write-Host "══════════════════════════════════════════`n" -ForegroundColor Cyan

# Admin check
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERREUR: Lancez en tant qu'Administrateur" -ForegroundColor Red
    exit 1
}

# Téléchargement Winlogbeat
$url      = "https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-$WinlogbeatVersion-windows-x86_64.zip"
$zipPath  = "$env:TEMP\winlogbeat.zip"
$tempPath = "$env:TEMP\winlogbeat-extract"

Write-Step "Téléchargement Winlogbeat $WinlogbeatVersion..."
Invoke-WebRequest -Uri $url -OutFile $zipPath
Write-OK "Téléchargement OK"

# Extraction
Write-Step "Extraction..."
if (Test-Path $tempPath) { Remove-Item $tempPath -Recurse -Force }
Expand-Archive -Path $zipPath -DestinationPath $tempPath
$extractedFolder = Get-ChildItem $tempPath | Select-Object -First 1
Write-OK "Extraction OK"

# Installation
Write-Step "Installation dans $InstallPath..."
if (Test-Path $InstallPath) {
    # Arrêter le service s'il tourne
    $svc = Get-Service -Name "winlogbeat" -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") {
        Stop-Service -Name "winlogbeat" -Force
        Write-Step "Service winlogbeat arrêté"
    }
}

if (-not (Test-Path $InstallPath)) {
    New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
}

Copy-Item "$($extractedFolder.FullName)\*" -Destination $InstallPath -Recurse -Force
Write-OK "Fichiers installés"

# Configuration
Write-Step "Configuration Winlogbeat → SIEM $SiemIP..."

$config = @"
winlogbeat.event_logs:
  - name: Security
    ignore_older: 72h
    event_id: 4624, 4625, 4634, 4648, 4672, 4720, 4722, 4723, 4724, 4725, 4726, 4728, 4732, 4740, 4688, 4689, 4719, 5140, 5156, 5157

  - name: System
    ignore_older: 72h
    event_id: 7034, 7035, 7036, 7045, 6005, 6006, 6008, 1074, 41

  - name: Application
    ignore_older: 48h
    level: error, critical, warning

  - name: Microsoft-Windows-PowerShell/Operational
    ignore_older: 24h
    event_id: 4103, 4104, 4105, 4106

  - name: Microsoft-Windows-Windows Defender/Operational
    ignore_older: 72h
    event_id: 1006, 1007, 1116, 1117, 5001, 5010

processors:
  - add_host_metadata: ~
  - add_fields:
      target: ''
      fields:
        collector: winlogbeat
        os_type: windows
        log_category: windows_event
        siem_source: $($env:COMPUTERNAME)

output.logstash:
  hosts: ["${SiemIP}:5044"]

# Fallback HTTP si Logstash non dispo
# output.http:
#   hosts: ["http://${SiemIP}:3000"]
#   path: "/ingest"
#   method: POST

logging.level: info
logging.to_files: true
logging.files:
  path: C:\ProgramData\winlogbeat\logs
  name: winlogbeat
  keepfiles: 7
"@

$config | Out-File -FilePath "$InstallPath\winlogbeat.yml" -Encoding utf8
Write-OK "Configuration créée"

# Installation service Windows
Write-Step "Installation service Windows..."
Set-Location $InstallPath
& ".\install-service-winlogbeat.ps1" 2>&1 | Out-Null
Write-OK "Service installé"

# Démarrage
Write-Step "Démarrage du service..."
Start-Service -Name "winlogbeat"
Start-Sleep -Seconds 3

$svc = Get-Service -Name "winlogbeat"
if ($svc.Status -eq "Running") {
    Write-OK "Service winlogbeat démarré"
} else {
    Write-Warn "Service non démarré — vérifiez les logs dans C:\ProgramData\winlogbeat\logs"
}

# Config démarrage automatique
Set-Service -Name "winlogbeat" -StartupType Automatic
Write-OK "Démarrage automatique activé"

# Nettoyage
Remove-Item $zipPath  -Force -ErrorAction SilentlyContinue
Remove-Item $tempPath -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "  ┌──────────────────────────────────────────┐" -ForegroundColor Cyan
Write-Host "  │     Winlogbeat installé avec succès      │" -ForegroundColor Cyan
Write-Host "  │                                          │" -ForegroundColor Cyan
Write-Host "  │  Machine : $($env:COMPUTERNAME)" -ForegroundColor Green
Write-Host "  │  SIEM    : $SiemIP" -ForegroundColor Green
Write-Host "  │  Service : winlogbeat (Automatique)      │" -ForegroundColor Green
Write-Host "  └──────────────────────────────────────────┘" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Les Windows Event Logs sont maintenant envoyés au SIEM." -ForegroundColor White
