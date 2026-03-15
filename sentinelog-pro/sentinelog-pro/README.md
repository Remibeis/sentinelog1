# SentineLog PRO — SIEM Production

SIEM complet et commercialisable, déployable sur **Windows Server** via Docker.

## Architecture

```
Machines surveillées
├── Linux/Network  → Syslog UDP/TCP → Fluent Bit
├── Windows        → Winlogbeat     → Backend API
└── Web servers    → Apache/Nginx   → Fluent Bit
                                         │
                                    Backend API (FastAPI)
                                         │
                                    Elasticsearch
                                    ├── Dashboard (8080)
                                    └── Kibana (5601)
                                         │
                                    Data Processor
                                    (criticité + corrélation)
```

## Déploiement rapide

```powershell
# En PowerShell Admin sur le Windows Server SIEM
Set-ExecutionPolicy Bypass -Scope Process -Force
.\scripts\deploy.ps1
```

## Déploiement manuel

```powershell
docker compose up -d --build
```

## Accès

| Service    | URL                        |
|------------|----------------------------|
| Dashboard  | http://VOTRE_IP:8080       |
| API        | http://VOTRE_IP:3000/docs  |
| Kibana     | http://VOTRE_IP:5601       |

## Collecter des logs Windows (Winlogbeat)

Sur chaque machine Windows à surveiller :

```powershell
# En Admin, remplacer VOTRE_IP_SIEM par l'IP du serveur SentineLog
.\scripts\install-winlogbeat.ps1 -SiemIP "VOTRE_IP_SIEM"
```

Événements collectés : connexions (4624/4625), création processus (4688),
comptes (4720/4726), lockouts (4740), PowerShell (4104), Defender (1116)...

## Envoyer des logs Syslog

```bash
# Depuis Linux
logger -n VOTRE_IP_SIEM -P 514 "message de test"

# Depuis un équipement réseau (Cisco, Fortinet, pfSense...)
# Pointer vers VOTRE_IP_SIEM:514 (UDP)
```

## Niveaux de criticité

| Niveau   | Score  | Exemples                                      |
|----------|--------|-----------------------------------------------|
| CRITICAL | 90–100 | Brute-force SSH, IDS alert, malware, SQLi     |
| HIGH     | 65–89  | Firewall block, HTTP 500, élévation privilège |
| MEDIUM   | 30–64  | HTTP 4xx, timeout réseau, erreur système      |
| LOW      | 15–29  | Auth réussie, warnings                        |
| INFO     | 1–14   | Accès HTTP normaux                            |

## Corrélations automatiques

- **BRUTE_FORCE_DETECTED** : ≥10 tentatives auth depuis même IP en 5min
- **PORTSCAN_SUSPECTED** : ≥20 connexions depuis même IP en 5min

## Maintenance

```powershell
# Arrêter
docker compose down

# Voir les logs d'un service
docker logs sentinelog-backend
docker logs sentinelog-processor
docker logs sentinelog-elasticsearch

# Redémarrer un service
docker compose restart backend-api

# Mettre à jour
git pull
docker compose up -d --build
```

## Ports utilisés

| Port | Protocole | Usage                    |
|------|-----------|--------------------------|
| 8080 | TCP       | Dashboard SIEM           |
| 3000 | TCP       | API FastAPI              |
| 5601 | TCP       | Kibana                   |
| 9200 | TCP       | Elasticsearch            |
| 514  | UDP       | Syslog UDP               |
| 5514 | TCP       | Syslog TCP               |
| 5140 | UDP       | Syslog direct API        |
| 2020 | TCP       | Fluent Bit monitoring    |
