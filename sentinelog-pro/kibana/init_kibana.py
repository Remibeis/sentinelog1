#!/usr/bin/env python3
"""
SentineLog PRO — Script d'initialisation Kibana (Secured)
"""
import json
import time
import os
import base64
import urllib.request
import urllib.error

KIBANA_URL = os.getenv("KIBANA_URL", "http://kibana:5601")
ES_URL     = os.getenv("ES_URL", "http://elasticsearch:9200")
ES_USER    = os.getenv("ES_USER", "elastic")
ES_PASS    = os.getenv("ES_PASSWORD", "changeme")

# Création du header Auth Basic
auth_str = f"{ES_USER}:{ES_PASS}"
auth_b64 = base64.b64encode(auth_str.encode()).decode()

HEADERS = {
    "Content-Type":  "application/json",
    "kbn-xsrf":      "true",
    "Authorization": f"Basic {auth_b64}"
}

def req(method, url, data=None):
    body = json.dumps(data).encode() if data else None
    r = urllib.request.Request(url, data=body, headers=HEADERS, method=method)
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        # print(f"  HTTP {e.code} on {url}: {e.read().decode()[:200]}")
        return None
    except Exception as e:
        print(f"  Erreur sur {url}: {e}")
        return None

def wait_kibana():
    print(f"Attente Kibana ({KIBANA_URL})...")
    for i in range(40):
        try:
            r = urllib.request.Request(f"{KIBANA_URL}/api/status", headers=HEADERS)
            with urllib.request.urlopen(r, timeout=5) as resp:
                data = json.loads(resp.read())
                status = data.get("status", {}).get("overall", {}).get("level")
                if status == "available":
                    print("Kibana OK ✓")
                    return True
        except Exception as e:
            pass
        print(f"  tentative {i+1}/40...")
        time.sleep(5)
    return False

def create_index_pattern(id, title):
    print(f"Création index pattern {title}...")
    req("POST", f"{KIBANA_URL}/api/saved_objects/index-pattern/{id}", {
        "attributes": {
            "title": title,
            "timeFieldName": "timestamp"
        }
    })

def create_dashboard():
    print("Création du dashboard principal...")
    # Simplifié pour l'exemple, on crée juste l'objet dashboard
    req("POST", f"{KIBANA_URL}/api/saved_objects/dashboard/sentinelog-main", {
        "attributes": {
            "title": "SentineLog PRO — Dashboard Principal",
            "description": "Vue d'ensemble sécurisée",
            "panelsJSON": "[]",
            "optionsJSON": "{\"useMargins\":true}",
            "timeRestore": false,
        }
    })

if __name__ == "__main__":
    print("=" * 50)
    print("  SentineLog PRO — Secured Init")
    print("=" * 50)

    if not wait_kibana():
        print("Kibana non disponible ou auth incorrecte. Arrêt.")
        exit(1)

    create_index_pattern("sentinelog-logs", "sentinelog-logs")
    create_index_pattern("sentinelog-alerts", "sentinelog-alerts")
    create_dashboard()

    print("\nInitialisation terminée avec succès ✓")
