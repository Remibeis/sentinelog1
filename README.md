# SentineLog SIEM — Version Python

SIEM (Security Information and Event Management) entièrement recodé en **Python**,
déployable sur **Windows Server** via Docker Desktop ou Docker Engine.

## Stack technique

| Composant        | Technologie              | Rôle                                      |
|------------------|--------------------------|-------------------------------------------|
| `backend-api`    | **Python 3.12 + FastAPI**| API REST, ingestion logs, syslog UDP      |
| `data-processor` | **Python 3.12**          | Enrichissement, criticité, corrélation    |
| `fluent-bit`     | Fluent Bit 2.2.3         | Collecte syslog UDP/TCP + fichiers        |
| `elasticsearch`  | Elasticsearch 8.12.0     | Stockage et indexation des logs           |
| `kibana`         | Kibana 8.12.0            | Visualisation avancée (optionnel)         |
| `frontend`       | HTML/JS + Nginx          | Dashboard SIEM temps réel                 |

---

## Démarrage rapide

### Prérequis
- Docker Desktop (Windows) ou Docker Engine + Docker Compose
- RAM recommandée : 4 Go minimum (Elasticsearch = 2 Go)

### Lancement

```bash
# Cloner / copier le dossier sentinelog-python sur le serveur
cd sentinelog-python

# Build et démarrage de tous les services
docker compose up -d --build

# Vérifier que tout est up
docker compose ps
```

### Accès

| Service          | URL                          |
|------------------|------------------------------|
| Dashboard SIEM   | http://localhost:8080        |
| API FastAPI docs | http://localhost:3000/docs   |
| Kibana           | http://localhost:5601        |
| Elasticsearch    | http://localhost:9200        |

---

## Niveaux de criticité

| Niveau     | Score  | Déclencheurs typiques                             |
|------------|--------|---------------------------------------------------|
| CRITICAL   | 90–100 | Brute-force SSH, alertes IDS/Suricata, malware    |
| HIGH       | 65–89  | Firewall block, erreurs HTTP 5xx, élévation priv. |
| MEDIUM     | 30–64  | Erreurs HTTP 4xx, timeout réseau, erreurs système |
| LOW        | 15–29  | Auth réussie, warnings système                    |
| INFO       | 1–14   | Accès HTTP normaux, logs génériques               |

---

## Corrélation automatique

Le `data-processor` détecte automatiquement :
- **BRUTE_FORCE_DETECTED** : ≥10 tentatives SSH depuis la même IP en 5 min
- **PORTSCAN_SUSPECTED** : ≥20 connexions depuis la même IP en 5 min

Les alertes corrélées sont indexées dans `sentinelog-alerts`.

---

## Envoi de logs vers le SIEM

### Syslog UDP (depuis Linux/Windows)
```bash
# Linux
logger -n <IP_SERVEUR> -P 514 "Test log depuis Linux"

# Depuis un autre conteneur Docker
echo "<14>Jan 1 12:00:00 host sshd[1234]: Failed password for invalid user admin from 10.0.0.1 port 22 ssh2" | nc -u <IP_SERVEUR> 514
```

### API REST (ingestion directe)
```bash
curl -X POST http://localhost:3000/ingest \
  -H "Content-Type: application/json" \
  -d '{"message": "Failed password for invalid user admin from 192.168.1.100 port 22 ssh2", "source": "ssh", "host": "webserver"}'
```

### Windows Event Log (via Winlogbeat ou NXLog)
Pointer Winlogbeat / NXLog vers `localhost:5514` (TCP syslog).

---

## Architecture

```
Windows Server
└── Docker
    ├── fluent-bit ──────────────────────┐
    │   (UDP 514, TCP 5514)              │
    │   (fichiers /var/log/*)            │  HTTP POST /ingest
    │                                    ▼
    ├── backend-api (FastAPI :3000) ──── ─ ─ ─► elasticsearch:9200
    │   • /ingest (Fluent Bit → ES)            (index: sentinelog-logs)
    │   • /logs   (lecture avec filtres)              │
    │   • /stats  (agrégations dashboard)             │
    │   • /alerts (HIGH + CRITICAL)                   │
    │                                                  │
    ├── data-processor (Python) ◄──────────────────── ┘
    │   • Enrichit les logs non-classifiés
    │   • Moteur de criticité (14 règles)
    │   • Corrélation (brute-force, scan)
    │   • Alertes → sentinelog-alerts
    │
    ├── frontend (Nginx :8080)
    │   Dashboard temps réel (refresh 15s)
    │
    └── kibana (:5601)
        Visualisation avancée / alertes Kibana
```

---

## Structure du projet

```
sentinelog-python/
├── backend-api/
│   ├── main.py           # FastAPI app (API + Syslog UDP)
│   ├── requirements.txt
│   └── Dockerfile
├── data-processor/
│   ├── main.py           # Enrichissement + corrélation
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── index.html        # Dashboard SIEM
│   ├── nginx.conf
│   └── Dockerfile
├── collector/
│   ├── fluent-bit.conf   # Config Fluent Bit
│   ├── parsers.conf      # Parsers regex (syslog, apache, nginx…)
│   └── state/            # État Fluent Bit (positions fichiers)
├── docker-compose.yaml
└── README.md
```
