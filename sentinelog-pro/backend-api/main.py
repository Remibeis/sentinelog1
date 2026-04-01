"""
SentineLog - Secured Backend API (Python/FastAPI)
"""
import os
import asyncio
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from elasticsearch import AsyncElasticsearch
from jose import JWTError, jwt
from passlib.context import CryptContext
import uvicorn

# Import de la logique partagée (Point 2 - DRY & RGPD)
from shared.logic import enrich_log, mask_ip

# ─── Configuration ───────────────────────────────────────────────────────────
ES_URL        = os.getenv("ES_URL", "http://elasticsearch:9200")
ES_USER       = os.getenv("ES_USER", "elastic")
ES_PASSWORD   = os.getenv("ES_PASSWORD", "changeme")
ES_INDEX      = os.getenv("ES_INDEX", "sentinelog-logs")
SYSLOG_PORT   = int(os.getenv("SYSLOG_PORT", "5140"))
API_PORT      = int(os.getenv("API_PORT", "3000"))

# Sécurité (Point 1)
JWT_SECRET     = os.getenv("JWT_SECRET", "super-secret-key-to-change")
ALGORITHM      = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s - %(message)s")
log = logging.getLogger("sentinelog.api")

# ─── Sécurité : Auth & JWT ──────────────────────────────────────────────────
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class Token(BaseModel):
    access_token: str
    token_type: str

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        return username
    except JWTError:
        raise credentials_exception

# ─── Elasticsearch Client ──────────────────────────────────────────────────
es: AsyncElasticsearch = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global es
    es = AsyncElasticsearch(
        [ES_URL],
        basic_auth=(ES_USER, ES_PASSWORD),
        verify_certs=False # En dev, on ignore TLS si auto-généré
    )
    await ensure_index()
    asyncio.create_task(start_syslog_udp())
    log.info(f"SentineLog API Secured → ES: {ES_URL}")
    yield
    await es.close()

app = FastAPI(title="SentineLog SIEM API", version="2.1.0", lifespan=lifespan)

# CORS Restreint (Security by Design)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8080"], # À adapter selon l'URL du frontend
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# ─── Modèles Pydantic ───────────────────────────────────────────────────────
class RawLog(BaseModel):
    message: str
    source: Optional[str] = "api"
    host: Optional[str] = None
    timestamp: Optional[str] = None

# ─── Initialisation de l'index ES ────────────────────────────────────────────
async def ensure_index():
    try:
        if not await es.indices.exists(index=ES_INDEX):
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
                        "ip_masked":      {"type": "keyword"}, # RGPD
                        "user":           {"type": "keyword"},
                        "rule_id":        {"type": "keyword"},
                    }
                }
            })
            log.info(f"Index {ES_INDEX} créé avec sécurité")
    except Exception as e:
        log.warning(f"ensure_index: {e}")

# ─── Serveur Syslog UDP (Isolé) ──────────────────────────────────────────────
class SyslogProtocol(asyncio.DatagramProtocol):
    def datagram_received(self, data: bytes, addr):
        message = data.decode("utf-8", errors="replace").strip()
        asyncio.create_task(self._ingest(message, addr[0]))

    async def _ingest(self, message: str, host: str):
        doc = enrich_log(message, source="syslog-udp", host=host)
        try:
            await es.index(index=ES_INDEX, document=doc)
        except Exception: pass

async def start_syslog_udp():
    loop = asyncio.get_running_loop()
    try:
        await loop.create_datagram_endpoint(SyslogProtocol, local_addr=("0.0.0.0", SYSLOG_PORT))
        log.info(f"Syslog UDP actif sur {SYSLOG_PORT}")
    except Exception as e:
        log.error(f"Syslog UDP erreur: {e}")

# ─── Routes API ──────────────────────────────────────────────────────────────

@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    # Comparaison simple pour l'admin (Security by Design: utilisation d'une variable d'env)
    if form_data.username == "admin" and form_data.password == ADMIN_PASSWORD:
        access_token = create_access_token(data={"sub": form_data.username})
        return {"access_token": access_token, "token_type": "bearer"}
    
    log.warning(f"Tentative de connexion échouée pour l'utilisateur: {form_data.username}")
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect username or password",
        headers={"WWW-Authenticate": "Bearer"},
    )

@app.get("/health")
async def health():
    return {"status": "ok"}

@app.post("/ingest", status_code=201)
async def ingest_log(raw: RawLog):
    """Ingestion anonyme autorisée (ex: collecteurs internes)."""
    doc = enrich_log(raw.message, source=raw.source, host=raw.host, timestamp=raw.timestamp)
    try:
        await es.index(index=ES_INDEX, document=doc)
        return {"status": "indexed"}
    except Exception as e:
        raise HTTPException(500, str(e))

@app.get("/logs")
async def get_logs(
    size: int = 100,
    search: Optional[str] = None,
    user: str = Depends(get_current_user) # Protection JWT
):
    query = {"match_all": {}}
    if search:
        query = {"match": {"message": search}}
    
    try:
        res = await es.search(index=ES_INDEX, size=size, sort=[{"timestamp": "desc"}], query=query)
        # RGPD: On renvoie l'IP masquée par défaut pour l'utilisateur
        logs = []
        for h in res["hits"]["hits"]:
            d = h["_source"]
            d["ip"] = d.get("ip_masked", "?.?.?.x") # Affichage sécurisé
            logs.append(d)
        return {"logs": logs}
    except Exception as e:
        raise HTTPException(500, str(e))

@app.get("/stats")
async def get_stats(user: str = Depends(get_current_user)):
    try:
        res = await es.search(index=ES_INDEX, size=0, aggs={
            "by_severity": {"terms": {"field": "severity"}},
            "by_category": {"terms": {"field": "category"}}
        })
        aggs = res.get("aggregations", {})
        return {
            "by_severity": {b["key"]: b["doc_count"] for b in aggs["by_severity"]["buckets"]},
            "by_category": {b["key"]: b["doc_count"] for b in aggs["by_category"]["buckets"]}
        }
    except Exception as e:
        raise HTTPException(500, str(e))

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=API_PORT)
