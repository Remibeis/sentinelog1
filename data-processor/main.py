"""
SentineLog - Data Processor (Python)
Remplace le data-processor Node.js.

Rôle :
  1. Récupère les logs bruts non-enrichis d'Elasticsearch
  2. Applique le moteur de criticité (règles + ML-like scoring)
  3. Détecte les corrélations (brute-force, port-scan, etc.)
  4. Crée des alertes corrélées dans l'index sentinelog-alerts
  5. Tourne en boucle toutes les N secondes
"""
import os
import re
import time
import logging
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from typing import Optional

from elasticsearch import Elasticsearch

# ─── Config ──────────────────────────────────────────────────────────────────
ES_URL           = os.getenv("ES_URL", "http://elasticsearch:9200")
ES_INDEX_LOGS    = os.getenv("ES_INDEX", "sentinelog-logs")
ES_INDEX_ALERTS  = "sentinelog-alerts"
POLL_INTERVAL    = int(os.getenv("POLL_INTERVAL", "10"))   # secondes
BATCH_SIZE       = int(os.getenv("BATCH_SIZE", "500"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
)
log = logging.getLogger("sentinelog.processor")

# ─── Règles de criticité ─────────────────────────────────────────────────────
SEVERITY_RULES = [
    # CRITICAL
    {
        "id": "SSH_FAILED_AUTH",
        "pattern": re.compile(r"Failed password|authentication failure|Invalid user", re.I),
        "severity": "CRITICAL", "score": 90,
        "category": "auth", "tags": ["brute-force", "ssh"]
    },
    {
        "id": "IDS_ALERT",
        "pattern": re.compile(r"suricata|ET SCAN|ET EXPLOIT|GPL ATTACK|EMERGING", re.I),
        "severity": "CRITICAL", "score": 95,
        "category": "ids", "tags": ["ids", "suricata", "alert"]
    },
    {
        "id": "WEB_ATTACK",
        "pattern": re.compile(r"SQL injection|XSS|sqlmap|union select|<script|\.\.\/|cmd=|exec\(", re.I),
        "severity": "CRITICAL", "score": 95,
        "category": "web", "tags": ["web-attack", "injection"]
    },
    {
        "id": "PRIVILEGE_ESC",
        "pattern": re.compile(r"sudo|su root|privilege escalation|NOPASSWD|setuid", re.I),
        "severity": "HIGH", "score": 80,
        "category": "auth", "tags": ["privilege-escalation"]
    },
    # HIGH
    {
        "id": "FIREWALL_BLOCK",
        "pattern": re.compile(r"\[UFW BLOCK\]|DROP|REJECT|iptables.*DROP", re.I),
        "severity": "HIGH", "score": 70,
        "category": "firewall", "tags": ["firewall", "blocked"]
    },
    {
        "id": "HTTP_SERVER_ERROR",
        "pattern": re.compile(r"HTTP/\S+ 5\d{2}|error 5\d{2}|Internal Server Error", re.I),
        "severity": "HIGH", "score": 65,
        "category": "web", "tags": ["http", "server-error"]
    },
    {
        "id": "MALWARE_INDICATOR",
        "pattern": re.compile(r"trojan|malware|ransomware|rootkit|backdoor|C2|command.and.control", re.I),
        "severity": "CRITICAL", "score": 98,
        "category": "malware", "tags": ["malware", "threat"]
    },
    # MEDIUM
    {
        "id": "HTTP_CLIENT_ERROR",
        "pattern": re.compile(r"HTTP/\S+ 4\d{2}|error 4\d{2}| 404 | 403 | 401 ", re.I),
        "severity": "MEDIUM", "score": 40,
        "category": "web", "tags": ["http", "client-error"]
    },
    {
        "id": "CONN_ISSUE",
        "pattern": re.compile(r"connection refused|connection timeout|ECONNREFUSED|ETIMEDOUT", re.I),
        "severity": "MEDIUM", "score": 35,
        "category": "network", "tags": ["connectivity"]
    },
    {
        "id": "SYSTEM_ERROR",
        "pattern": re.compile(r"\berror\b|\bfailed\b|\bfailure\b", re.I),
        "severity": "MEDIUM", "score": 30,
        "category": "system", "tags": ["error"]
    },
    # LOW
    {
        "id": "AUTH_SUCCESS",
        "pattern": re.compile(r"Accepted password|session opened|logged in|login success", re.I),
        "severity": "LOW", "score": 15,
        "category": "auth", "tags": ["auth", "success"]
    },
    {
        "id": "SYSTEM_WARN",
        "pattern": re.compile(r"\bwarning\b|\bwarn\b", re.I),
        "severity": "LOW", "score": 20,
        "category": "system", "tags": ["warning"]
    },
    # INFO
    {
        "id": "HTTP_ACCESS",
        "pattern": re.compile(r"(GET|POST|PUT|DELETE|HEAD|OPTIONS) /"),
        "severity": "INFO", "score": 5,
        "category": "web", "tags": ["http", "access"]
    },
]

IP_RE   = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
USER_RE = re.compile(r"(?:for(?:\s+invalid)?\s+user\s+|user=)([a-zA-Z0-9_\-\.]+)", re.I)

def classify_message(message: str) -> dict:
    for rule in SEVERITY_RULES:
        if rule["pattern"].search(message):
            ip_m   = IP_RE.search(message)
            user_m = USER_RE.search(message)
            return {
                "rule_id":        rule["id"],
                "severity":       rule["severity"],
                "severity_score": rule["score"],
                "category":       rule["category"],
                "tags":           list(rule["tags"]),
                "ip":             ip_m.group(1) if ip_m else None,
                "user":           user_m.group(1) if user_m else None,
            }
    ip_m = IP_RE.search(message)
    return {
        "rule_id":        "GENERIC",
        "severity":       "INFO",
        "severity_score": 1,
        "category":       "generic",
        "tags":           [],
        "ip":             ip_m.group(1) if ip_m else None,
        "user":           None,
    }

# ─── Moteur de corrélation ───────────────────────────────────────────────────
# On garde en mémoire un compteur d'événements par IP sur fenêtre glissante 5min
_ip_events: dict = defaultdict(list)   # ip → [datetime, ...]
_ip_alerts_sent: dict = {}              # ip → last_alert_time

BRUTE_FORCE_THRESHOLD = 10   # tentatives SSH en 5 min → alerte
SCAN_THRESHOLD        = 20   # connexions différentes en 5 min → alerte

def update_ip_tracking(ip: Optional[str], category: str, ts: datetime):
    if not ip:
        return
    now = datetime.now(timezone.utc)
    _ip_events[ip].append((now, category))
    # Purge > 10 min
    _ip_events[ip] = [(t, c) for t, c in _ip_events[ip] if now - t < timedelta(minutes=10)]

def detect_correlations(es_client: Elasticsearch) -> list:
    alerts = []
    now = datetime.now(timezone.utc)
    window = timedelta(minutes=5)

    for ip, events in list(_ip_events.items()):
        recent = [(t, c) for t, c in events if now - t < window]
        auth_failures = [e for e in recent if "brute-force" in e[1] or e[1] == "auth"]
        any_events    = recent

        # Brute-force SSH
        if len(auth_failures) >= BRUTE_FORCE_THRESHOLD:
            last_sent = _ip_alerts_sent.get(f"bf_{ip}")
            if not last_sent or now - last_sent > timedelta(minutes=10):
                _ip_alerts_sent[f"bf_{ip}"] = now
                alerts.append({
                    "timestamp":   now.isoformat(),
                    "type":        "CORRELATION",
                    "rule":        "BRUTE_FORCE_DETECTED",
                    "severity":    "CRITICAL",
                    "score":       99,
                    "ip":          ip,
                    "description": f"Brute-force SSH détecté: {len(auth_failures)} tentatives depuis {ip} en 5 min",
                    "tags":        ["correlation", "brute-force", "ssh"],
                    "count":       len(auth_failures),
                })
                log.warning(f"[CORREL] BRUTE-FORCE depuis {ip} ({len(auth_failures)} tentatives)")

        # Port scan (beaucoup d'events réseau différents)
        if len(any_events) >= SCAN_THRESHOLD:
            last_sent = _ip_alerts_sent.get(f"scan_{ip}")
            if not last_sent or now - last_sent > timedelta(minutes=10):
                _ip_alerts_sent[f"scan_{ip}"] = now
                alerts.append({
                    "timestamp":   now.isoformat(),
                    "type":        "CORRELATION",
                    "rule":        "PORTSCAN_SUSPECTED",
                    "severity":    "HIGH",
                    "score":       85,
                    "ip":          ip,
                    "description": f"Scan potentiel depuis {ip}: {len(any_events)} connexions en 5 min",
                    "tags":        ["correlation", "scan", "network"],
                    "count":       len(any_events),
                })
                log.warning(f"[CORREL] SCAN depuis {ip} ({len(any_events)} events)")

    return alerts

# ─── Traitement des logs bruts ───────────────────────────────────────────────
def ensure_alerts_index(es_client: Elasticsearch):
    if not es_client.indices.exists(index=ES_INDEX_ALERTS):
        es_client.indices.create(index=ES_INDEX_ALERTS, body={
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "type":      {"type": "keyword"},
                    "rule":      {"type": "keyword"},
                    "severity":  {"type": "keyword"},
                    "score":     {"type": "integer"},
                    "ip":        {"type": "ip"},
                    "description": {"type": "text"},
                    "tags":      {"type": "keyword"},
                    "count":     {"type": "integer"},
                }
            },
            "settings": {"number_of_shards": 1, "number_of_replicas": 0}
        })
        log.info(f"Index {ES_INDEX_ALERTS} créé")

def process_unenriched(es_client: Elasticsearch):
    """Récupère les logs sans severity, les enrichit et les met à jour."""
    try:
        result = es_client.search(
            index=ES_INDEX_LOGS,
            size=BATCH_SIZE,
            query={"bool": {"must_not": [{"exists": {"field": "severity"}}]}},
            sort=[{"timestamp": {"order": "asc"}}]
        )
        hits = result["hits"]["hits"]
        if not hits:
            return 0

        ops = []
        for hit in hits:
            doc_id  = hit["_id"]
            message = hit["_source"].get("message", "")
            ts_str  = hit["_source"].get("timestamp", datetime.now(timezone.utc).isoformat())
            
            try:
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            except Exception:
                ts = datetime.now(timezone.utc)

            classified = classify_message(message)
            update_ip_tracking(classified["ip"], classified["category"], ts)

            ops.append({"update": {"_index": ES_INDEX_LOGS, "_id": doc_id}})
            ops.append({"doc": {
                "severity":       classified["severity"],
                "severity_score": classified["severity_score"],
                "category":       classified["category"],
                "tags":           classified["tags"],
                "ip":             classified["ip"],
                "user":           classified["user"],
                "rule_id":        classified["rule_id"],
                "enriched_at":    datetime.now(timezone.utc).isoformat(),
            }})

        if ops:
            es_client.bulk(body=ops)
            log.info(f"[PROCESS] {len(hits)} logs enrichis")

        return len(hits)

    except Exception as e:
        log.error(f"Erreur process_unenriched: {e}")
        return 0

def run_processor():
    log.info(f"Data Processor démarré → ES: {ES_URL}, index: {ES_INDEX_LOGS}")
    
    es_client = None
    # Retry connexion ES
    for attempt in range(30):
        try:
            es_client = Elasticsearch([ES_URL])
            if es_client.ping():
                log.info("Connecté à Elasticsearch ✓")
                break
        except Exception:
            pass
        log.warning(f"Attente ES... tentative {attempt+1}/30")
        time.sleep(5)
    else:
        log.critical("Impossible de se connecter à Elasticsearch après 30 tentatives")
        return

    ensure_alerts_index(es_client)

    log.info(f"Boucle de traitement active (interval: {POLL_INTERVAL}s)")
    while True:
        try:
            n_enriched = process_unenriched(es_client)

            corr_alerts = detect_correlations(es_client)
            for alert in corr_alerts:
                es_client.index(index=ES_INDEX_ALERTS, document=alert)
                log.info(f"[ALERT] {alert['rule']} depuis {alert.get('ip', '?')}")

            if n_enriched or corr_alerts:
                log.info(f"Cycle: {n_enriched} enrichis, {len(corr_alerts)} alertes corrélées")

        except Exception as e:
            log.error(f"Erreur boucle: {e}")

        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    run_processor()
