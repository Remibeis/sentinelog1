# ══════════════════════════════════════════════════════════════════════
#  SentineLog PRO — Script de déploiement Windows Server
#  Lance en PowerShell Administrator :
#  Set-ExecutionPolicy Bypass -Scope Process -Force
#  .\deploy.ps1
# ══════════════════════════════════════════════════════════════════════

param(
    [string]$InstallPath = "C:\SentineLog",
    [string]$ServerIP    = "localhost"
)

$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"

function Write-Header { param($msg)
    Write-Host "`n══════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  $msg" -ForegroundColor Cyan
    Write-Host "══════════════════════════════════" -ForegroundColor Cyan
}

function Write-OK    { param($msg) Write-Host "  ✓ $msg" -ForegroundColor Green }
function Write-Warn  { param($msg) Write-Host "  ⚠ $msg" -ForegroundColor Yellow }
function Write-Fail  { param($msg) Write-Host "  ✗ $msg" -ForegroundColor Red }
function Write-Step  { param($msg) Write-Host "  → $msg" -ForegroundColor White }

# ── Vérifications préalables ──────────────────────────────────────────
Write-Header "SentineLog PRO — Déploiement Windows Server"

# Admin check
$currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Fail "Ce script doit être lancé en tant qu'Administrateur"
    exit 1
}
Write-OK "Droits administrateur confirmés"

# Docker check
try {
    $dockerVersion = docker --version 2>&1
    Write-OK "Docker détecté: $dockerVersion"
} catch {
    Write-Fail "Docker non installé. Installez Docker Desktop."
    Start-Process "https://www.docker.com/products/docker-desktop/"
    exit 1
}

# Docker running check
try {
    docker ps 2>&1 | Out-Null
    Write-OK "Docker Engine actif"
} catch {
    Write-Fail "Docker Desktop n'est pas lancé. Démarrez Docker Desktop."
    exit 1
}

# ── Création des dossiers ─────────────────────────────────────────────
Write-Header "Création de la structure"

$dirs = @(
    "$InstallPath",
    "$InstallPath\data\elasticsearch",
    "$InstallPath\logs",
    "$InstallPath\collector\state",
    "$InstallPath\winlogbeat"
)

foreach ($dir in $dirs) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-OK "Créé: $dir"
    } else {
        Write-Step "Existe déjà: $dir"
    }
}

# ── Copie des fichiers ────────────────────────────────────────────────
Write-Header "Copie des fichiers"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

if (Test-Path "$scriptDir\docker-compose.yaml") {
    Copy-Item "$scriptDir\*" -Destination $InstallPath -Recurse -Force -Exclude "deploy.ps1","install-winlogbeat.ps1"
    Write-OK "Fichiers copiés vers $InstallPath"
} else {
    Write-Warn "Lancez ce script depuis le dossier SentineLog"
}

# ── Configuration réseau Windows Firewall ─────────────────────────────
Write-Header "Configuration du Pare-feu Windows"

$rules = @(
    @{Name="SentineLog-Dashboard";    Port=8080;  Protocol="TCP"; Desc="SentineLog Dashboard"},
    @{Name="SentineLog-API";          Port=3000;  Protocol="TCP"; Desc="SentineLog API"},
    @{Name="SentineLog-Kibana";       Port=5601;  Protocol="TCP"; Desc="SentineLog Kibana"},
    @{Name="SentineLog-Elasticsearch";Port=9200;  Protocol="TCP"; Desc="SentineLog Elasticsearch"},
    @{Name="SentineLog-Syslog-UDP";   Port=514;   Protocol="UDP"; Desc="SentineLog Syslog UDP"},
    @{Name="SentineLog-Syslog-TCP";   Port=5514;  Protocol="TCP"; Desc="SentineLog Syslog TCP"}
)

foreach ($rule in $rules) {
    $existing = Get-NetFirewallRule -DisplayName $rule.Name -ErrorAction SilentlyContinue
    if (-not $existing) {
        New-NetFirewallRule `
            -DisplayName $rule.Name `
            -Direction Inbound `
            -Protocol $rule.Protocol `
            -LocalPort $rule.Port `
            -Action Allow `
            -Description $rule.Desc | Out-Null
        Write-OK "Règle ajoutée: $($rule.Name) ($($rule.Protocol)/$($rule.Port))"
    } else {
        Write-Step "Règle existante: $($rule.Name)"
    }
}

# ── Lancement Docker Compose ──────────────────────────────────────────
Write-Header "Lancement de la stack Docker"

Set-Location $InstallPath

Write-Step "Pulling les images..."
docker compose pull 2>&1 | ForEach-Object { Write-Step $_ }

Write-Step "Build et démarrage des services..."
docker compose up -d --build 2>&1 | ForEach-Object { Write-Step $_ }

# ── Attente démarrage ─────────────────────────────────────────────────
Write-Header "Vérification des services"
Write-Step "Attente 30 secondes que les services démarrent..."
Start-Sleep -Seconds 30

$services = @(
    @{Name="Elasticsearch"; URL="http://localhost:9200/_cluster/health"},
    @{Name="API Backend";   URL="http://localhost:3000/health"},
    @{Name="Dashboard";     URL="http://localhost:8080"},
    @{Name="Kibana";        URL="http://localhost:5601/api/status"}
)

foreach ($svc in $services) {
    try {
        $resp = Invoke-WebRequest -Uri $svc.URL -TimeoutSec 5 -UseBasicParsing
        if ($resp.StatusCode -eq 200) {
            Write-OK "$($svc.Name) → UP ($($svc.URL))"
        } else {
            Write-Warn "$($svc.Name) → HTTP $($resp.StatusCode)"
        }
    } catch {
        Write-Warn "$($svc.Name) → Non disponible encore (normal si ES démarre)"
    }
}

# ── Init Kibana ───────────────────────────────────────────────────────
Write-Header "Initialisation Kibana"
Write-Step "Configuration des index patterns et dashboards..."

if (Get-Command python -ErrorAction SilentlyContinue) {
    python "$InstallPath\kibana\init_kibana.py"
    Write-OK "Kibana initialisé"
} elseif (Get-Command python3 -ErrorAction SilentlyContinue) {
    python3 "$InstallPath\kibana\init_kibana.py"
    Write-OK "Kibana initialisé"
} else {
    Write-Warn "Python non disponible — init Kibana manuelle requise"
    Write-Step "Ouvrez http://localhost:5601 et créez l'index pattern 'sentinelog-logs'"
}

# ── Résumé ────────────────────────────────────────────────────────────
Write-Header "Déploiement terminé"
$ip = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.*"} | Select-Object -First 1).IPAddress

Write-Host ""
Write-Host "  ┌─────────────────────────────────────────────┐" -ForegroundColor Cyan
Write-Host "  │         SENTINELOG PRO — ACCÈS              │" -ForegroundColor Cyan
Write-Host "  ├─────────────────────────────────────────────┤" -ForegroundColor Cyan
Write-Host "  │ Dashboard  → http://${ip}:8080              │" -ForegroundColor Green
Write-Host "  │ API Docs   → http://${ip}:3000/docs         │" -ForegroundColor Green
Write-Host "  │ Kibana     → http://${ip}:5601              │" -ForegroundColor Green
Write-Host "  │ Syslog UDP → ${ip}:514                      │" -ForegroundColor Yellow
Write-Host "  │ Syslog TCP → ${ip}:5514                     │" -ForegroundColor Yellow
Write-Host "  └─────────────────────────────────────────────┘" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Pour envoyer des logs depuis d'autres machines :" -ForegroundColor White
Write-Host "  logger -n $ip -P 514 'Test SentineLog'" -ForegroundColor Gray
Write-Host ""
Write-OK "SentineLog PRO opérationnel !"
