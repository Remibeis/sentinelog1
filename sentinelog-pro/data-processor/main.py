"""
SentineLog - Secured Data Processor (Python)
Rôle : Enrichissement et Corrélation persistante via Redis.
"""
import os
import time
import logging
import json
from datetime import datetime, timezone, timedelta
from typing import Optional

from elasticsearch import Elasticsearch
import redis

# Import de la logique partagée (Point 2 - DRY)
from shared.logic import classify_log, mask_ip

# ─── Configuration ───────────────────────────────────────────────────────────
ES_URL          = os.getenv("ES_URL", "http://elasticsearch:9200")
ES_USER         = os.getenv("ES_USER", "elastic")
ES_PASSWORD     = os.getenv("ES_PASSWORD", "changeme")
ES_INDEX_LOGS   = os.getenv("ES_INDEX", "sentinelog-logs")
ES_INDEX_ALERTS = "sentinelog-alerts"
REDIS_URL       = os.getenv("REDIS_URL", "redis://redis:6379/0")

POLL_INTERVAL   = int(os.getenv("POLL_INTERVAL", "10"))
BATCH_SIZE      = 500

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s - %(message)s")
log = logging.getLogger("sentinelog.processor")

# ─── Connexion Redis (State Management) ──────────────────────────────────────
r = redis.from_url(REDIS_URL, decode_responses=True)

def track_ip_event(ip: str, category: str):
    """Stocke l'événement dans Redis avec une expiration de 10 min."""
    if not ip: return
    key = f"sentinelog:events:{ip}"
    now = datetime.now(timezone.utc).timestamp()
    # On ajoute l'événement avec le timestamp comme score
    r.zadd(key, {f"{now}:{category}": now})
    # Nettoyage automatique des vieux événements (> 10 min)
    r.zremrangebyscore(key, 0, now - 600)
    r.expire(key, 600)

def get_recent_events_count(ip: str, category_filter: Optional[str] = None):
    key = f"sentinelog:events:{ip}"
    now = datetime.now(timezone.utc).timestamp()
    events = r.zrangebyscore(key, now - 300, now) # Fenêtre de 5 min
    if not category_filter:
        return len(events)
    return len([e for e in events if category_filter in e])

# ─── Moteur de Corrélation ───────────────────────────────────────────────────
def detect_alerts(es: Elasticsearch, ip: str):
    """Détecte les anomalies basées sur l'historique Redis."""
    if not ip: return
    
    # Seuil Brute-force
    bf_count = get_recent_events_count(ip, "auth")
    if bf_count >= 10:
        alert_key = f"sentinelog:alert_sent:bf:{ip}"
        if not r.get(alert_key):
            alert = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "type": "CORRELATION",
                "rule": "BRUTE_FORCE_DETECTED",
                "severity": "CRITICAL",
                "ip": ip,
                "ip_masked": mask_ip(ip),
                "description": f"Brute-force suspecté : {bf_count} échecs en 5min",
                "tags": ["correlation", "brute-force"]
            }
            es.index(index=ES_INDEX_ALERTS, document=alert)
            r.setex(alert_key, 600, "1") # Anti-spam 10 min
            log.warning(f"ALERTE CORRÉLÉE : Brute-force depuis {ip}")

# ─── Traitement Principal ────────────────────────────────────────────────────
def process_logs(es: Elasticsearch):
    try:
        # On cherche les logs qui n'ont pas encore de rule_id (non enrichis)
        res = es.search(index=ES_INDEX_LOGS, size=BATCH_SIZE, query={
            "bool": {"must_not": [{"exists": {"field": "rule_id"}}]}
        })
        hits = res["hits"]["hits"]
        if not hits: return

        for hit in hits:
            doc_id = hit["_id"]
            source = hit["_source"]
            msg = source.get("message", "")
            
            # Utilisation de la logique partagée
            classified = classify_log(msg)
            
            # Update ES avec enrichissement
            es.update(index=ES_INDEX_LOGS, id=doc_id, doc={
                "severity":       classified["severity"],
                "severity_score": classified["severity_score"],
                "category":       classified["category"],
                "ip":             classified["ip"],
                "ip_masked":      mask_ip(classified["ip"]),
                "rule_id":        classified["rule_id"],
                "enriched_at":    datetime.now(timezone.utc).isoformat()
            })

            # Tracking Redis pour corrélation
            if classified["ip"]:
                track_ip_event(classified["ip"], classified["category"])
                detect_alerts(es, classified["ip"])

        log.info(f"Traitement de {len(hits)} logs terminé.")
    except Exception as e:
        log.error(f"Erreur traitement : {e}")

def run():
    log.info("Démarrage du Data Processor sécurisé...")
    es = Elasticsearch([ES_URL], basic_auth=(ES_USER, ES_PASSWORD))
    
    # Création de l'index d'alertes si besoin
    if not es.indices.exists(index=ES_INDEX_ALERTS):
        es.indices.create(index=ES_INDEX_ALERTS)

    while True:
        process_logs(es)
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    run()
