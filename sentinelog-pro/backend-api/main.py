"""
SentineLog - Backend API (Python/FastAPI)
Remplace le backend Node.js/Express
"""
import os
import re
import socket
import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional, List
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from elasticsearch import AsyncElasticsearch, NotFoundError
import uvicorn

# ─── Configuration ───────────────────────────────────────────────────────────
ES_URL       = os.getenv("ES_URL", "http://elasticsearch:9200")
ES_INDEX     = os.getenv("ES_INDEX", "sentinelog-logs")
SYSLOG_PORT  = int(os.getenv("SYSLOG_PORT", "514"))
API_PORT     = int(os.getenv("API_PORT", "3000"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
)
log = logging.getLogger("sentinelog.api")

# ─── Elasticsearch client (global) ───────────────────────────────────────────
es: AsyncElasticsearch = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global es
    es = AsyncElasticsearch([ES_URL])
    await ensure_index()
    # Démarrer serveur syslog UDP en background
    asyncio.create_task(start_syslog_udp())
    log.info(f"SentineLog API démarré → ES: {ES_URL}")
    yield
    await es.close()

app = FastAPI(
    title="SentineLog SIEM API",
    description="SIEM backend Python/FastAPI — collecte, enrichit et stocke les logs",
    version="2.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Modèles Pydantic ─────────────────────────────────────────────────────────
class RawLog(BaseModel):
    message: str
    source: Optional[str] = "api"
    host: Optional[str] = None
    timestamp: Optional[str] = None

class LogDocument(BaseModel):
    timestamp: str
    message: str
    source: str
    host: Optional[str] = None
    severity: str         # INFO / LOW / MEDIUM / HIGH / CRITICAL
    severity_score: int   # 0-100
    category: str         # ssh / web / firewall / system / auth / suricata / generic
    ip: Optional[str] = None
    user: Optional[str] = None
    tags: List[str] = []
    raw: Optional[str] = None

# ─── Moteur de criticité ─────────────────────────────────────────────────────
RULES = [
    # CRITICAL
    {"pattern": r"(Failed password|authentication failure|Invalid user)",
     "severity": "CRITICAL", "score": 90, "category": "auth",
     "tags": ["brute-force", "ssh"]},
    {"pattern": r"(\[UFW BLOCK\]|DROP|REJECT)",
     "severity": "HIGH",     "score": 70, "category": "firewall",
     "tags": ["firewall", "blocked"]},
    {"pattern": r"(suricata|ET SCAN|ET EXPLOIT|GPL ATTACK)",
     "severity": "CRITICAL", "score": 95, "category": "ids",
     "tags": ["ids", "suricata", "alert"]},
    {"pattern": r"(SQL injection|XSS|sqlmap|union select|<script)",
     "severity": "CRITICAL", "score": 95, "category": "web",
     "tags": ["web-attack", "injection"]},
    {"pattern": r"(error 500|Internal Server Error)",
     "severity": "HIGH",     "score": 65, "category": "web",
     "tags": ["http", "error"]},
    {"pattern": r"(sudo|su root|privilege escalation|NOPASSWD)",
     "severity": "HIGH",     "score": 75, "category": "auth",
     "tags": ["privilege-escalation"]},
    # MEDIUM
    {"pattern": r"(error 4[0-9]{2}|404|403|401)",
     "severity": "MEDIUM",   "score": 40, "category": "web",
     "tags": ["http", "client-error"]},
    {"pattern": r"(connection refused|connection timeout|ECONNREFUSED)",
     "severity": "MEDIUM",   "score": 35, "category": "network",
     "tags": ["connectivity"]},
    {"pattern": r"(warning|WARN)",
     "severity": "LOW",      "score": 20, "category": "system",
     "tags": ["warning"]},
    # LOW/INFO
    {"pattern": r"(Accepted password|session opened|logged in)",
     "severity": "LOW",      "score": 15, "category": "auth",
     "tags": ["auth", "success"]},
    {"pattern": r"(GET|POST|PUT|DELETE) /",
     "severity": "INFO",     "score": 5,  "category": "web",
     "tags": ["http", "access"]},
]

IP_RE   = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
USER_RE = re.compile(r"(?:for(?: invalid)? user |user=)([a-zA-Z0-9_\-\.]+)")

def classify(message: str) -> dict:
    msg_lower = message.lower()
    for rule in RULES:
        if re.search(rule["pattern"], message, re.IGNORECASE):
            ip_match   = IP_RE.search(message)
            user_match = USER_RE.search(message)
            return {
                "severity":       rule["severity"],
                "severity_score": rule["score"],
                "category":       rule["category"],
                "tags":           rule["tags"],
                "ip":             ip_match.group(1) if ip_match else None,
                "user":           user_match.group(1) if user_match else None,
            }
    # Défaut
    ip_match = IP_RE.search(message)
    return {
        "severity":       "INFO",
        "severity_score": 1,
        "category":       "generic",
        "tags":           [],
        "ip":             ip_match.group(1) if ip_match else None,
        "user":           None,
    }

def enrich(raw: RawLog) -> dict:
    classified = classify(raw.message)
    return {
        "timestamp":       raw.timestamp or datetime.now(timezone.utc).isoformat(),
        "message":         raw.message,
        "source":          raw.source or "unknown",
        "host":            raw.host or socket.gethostname(),
        "severity":        classified["severity"],
        "severity_score":  classified["severity_score"],
        "category":        classified["category"],
        "tags":            classified["tags"],
        "ip":              classified["ip"],
        "user":            classified["user"],
        "raw":             raw.message,
    }

# ─── Initialisation de l'index ES ────────────────────────────────────────────
async def ensure_index():
    try:
        exists = await es.indices.exists(index=ES_INDEX)
        if not exists:
            await es.indices.create(index=ES_INDEX, body={
                "mappings": {
                    "properties": {
                        "timestamp":      {"type": "date"},
                        "message":        {"type": "text"},
                        "source":         {"type": "keyword"},
                        "host":           {"type": "keyword"},
                        "severity":       {"type": "keyword"},
                        "severity_score": {"type": "integer"},
                        "category":       {"type": "keyword"},
                        "tags":           {"type": "keyword"},
                        "ip":             {"type": "ip"},
                        "user":           {"type": "keyword"},
                    }
                },
                "settings": {
                    "number_of_shards":   1,
                    "number_of_replicas": 0,
                }
            })
            log.info(f"Index {ES_INDEX} créé")
    except Exception as e:
        log.warning(f"ensure_index: {e}")

# ─── Serveur Syslog UDP ───────────────────────────────────────────────────────
class SyslogProtocol(asyncio.DatagramProtocol):
    def datagram_received(self, data: bytes, addr):
        message = data.decode("utf-8", errors="replace").strip()
        asyncio.create_task(self._ingest(message, addr[0]))

    async def _ingest(self, message: str, host: str):
        doc = enrich(RawLog(message=message, source="syslog-udp", host=host))
        try:
            await es.index(index=ES_INDEX, document=doc)
        except Exception as e:
            log.error(f"Syslog UDP → ES erreur: {e}")

async def start_syslog_udp():
    loop = asyncio.get_running_loop()
    try:
        await loop.create_datagram_endpoint(
            SyslogProtocol,
            local_addr=("0.0.0.0", SYSLOG_PORT)
        )
        log.info(f"Syslog UDP démarré sur port {SYSLOG_PORT}")
    except PermissionError:
        log.warning(f"Port {SYSLOG_PORT} non disponible (nécessite root). Syslog UDP ignoré.")
    except Exception as e:
        log.error(f"Syslog UDP erreur: {e}")

# ─── Routes API ──────────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    try:
        ping = await es.ping()
        return {"status": "ok", "elasticsearch": ping}
    except Exception as e:
        raise HTTPException(503, f"ES indisponible: {e}")

@app.post("/ingest", status_code=201)
async def ingest_log(raw: RawLog):
    """Point d'entrée pour Fluent Bit ou n'importe quelle source."""
    doc = enrich(raw)
    try:
        resp = await es.index(index=ES_INDEX, document=doc)
        return {"status": "indexed", "id": resp["_id"], "severity": doc["severity"]}
    except Exception as e:
        log.error(f"Ingest erreur: {e}")
        raise HTTPException(500, f"Erreur Elasticsearch: {e}")

@app.get("/logs")
async def get_logs(
    size:     int           = Query(200, ge=1, le=1000),
    severity: Optional[str] = Query(None, description="INFO|LOW|MEDIUM|HIGH|CRITICAL"),
    category: Optional[str] = Query(None),
    search:   Optional[str] = Query(None),
    from_ts:  Optional[str] = Query(None, description="ISO 8601"),
    to_ts:    Optional[str] = Query(None, description="ISO 8601"),
):
    """Récupère les logs avec filtres optionnels."""
    must = []
    if severity:
        must.append({"term": {"severity": severity.upper()}})
    if category:
        must.append({"term": {"category": category.lower()}})
    if search:
        must.append({"match": {"message": search}})
    if from_ts or to_ts:
        range_filter = {"timestamp": {}}
        if from_ts: range_filter["timestamp"]["gte"] = from_ts
        if to_ts:   range_filter["timestamp"]["lte"] = to_ts
        must.append({"range": range_filter})

    query = {"bool": {"must": must}} if must else {"match_all": {}}

    try:
        result = await es.search(
            index=ES_INDEX,
            size=size,
            sort=[{"timestamp": {"order": "desc"}}],
            query=query
        )
        logs = [hit["_source"] | {"_id": hit["_id"]} for hit in result["hits"]["hits"]]
        total = result["hits"]["total"]["value"]
        return {"total": total, "logs": logs}
    except Exception as e:
        log.error(f"Get logs erreur: {e}")
        raise HTTPException(500, f"Erreur Elasticsearch: {e}")

@app.get("/stats")
async def get_stats():
    """Statistiques globales pour le dashboard."""
    try:
        # Agrégations
        agg_result = await es.search(
            index=ES_INDEX,
            size=0,
            query={"match_all": {}},
            aggs={
                "by_severity": {
                    "terms": {"field": "severity", "size": 10}
                },
                "by_category": {
                    "terms": {"field": "category", "size": 10}
                },
                "by_hour": {
                    "date_histogram": {
                        "field": "timestamp",
                        "calendar_interval": "hour",
                        "min_doc_count": 0
                    }
                },
                "top_ips": {
                    "terms": {"field": "ip", "size": 10, "missing": "0.0.0.0"}
                },
                "critical_last_24h": {
                    "filter": {
                        "bool": {
                            "must": [
                                {"terms": {"severity": ["HIGH", "CRITICAL"]}},
                                {"range": {"timestamp": {"gte": "now-24h"}}}
                            ]
                        }
                    }
                }
            }
        )

        aggs = agg_result.get("aggregations", {})
        total = agg_result["hits"]["total"]["value"]

        return {
            "total_logs": total,
            "by_severity": {
                b["key"]: b["doc_count"]
                for b in aggs.get("by_severity", {}).get("buckets", [])
            },
            "by_category": {
                b["key"]: b["doc_count"]
                for b in aggs.get("by_category", {}).get("buckets", [])
            },
            "timeline": [
                {"time": b["key_as_string"], "count": b["doc_count"]}
                for b in aggs.get("by_hour", {}).get("buckets", [])[-24:]
            ],
            "top_ips": [
                {"ip": b["key"], "count": b["doc_count"]}
                for b in aggs.get("top_ips", {}).get("buckets", [])
                if b["key"] != "__none__"
            ],
            "critical_24h": aggs.get("critical_last_24h", {}).get("doc_count", 0),
        }
    except Exception as e:
        log.error(f"Stats erreur: {e}")
        raise HTTPException(500, f"Erreur: {e}")

@app.get("/alerts")
async def get_alerts(size: int = Query(50, ge=1, le=500)):
    """Retourne uniquement les logs HIGH et CRITICAL."""
    try:
        result = await es.search(
            index=ES_INDEX,
            size=size,
            sort=[{"timestamp": {"order": "desc"}}],
            query={"terms": {"severity": ["HIGH", "CRITICAL"]}}
        )
        return {
            "total": result["hits"]["total"]["value"],
            "alerts": [h["_source"] | {"_id": h["_id"]} for h in result["hits"]["hits"]]
        }
    except Exception as e:
        raise HTTPException(500, f"Erreur: {e}")

# ─── Entrypoint ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=API_PORT, reload=False)
