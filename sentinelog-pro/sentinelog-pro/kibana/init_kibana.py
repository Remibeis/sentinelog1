#!/usr/bin/env python3
"""
SentineLog PRO — Script d'initialisation Kibana
Crée automatiquement :
  - Index patterns
  - Saved searches
  - Visualisations
  - Dashboard principal
"""
import json
import time
import urllib.request
import urllib.error

KIBANA_URL = "http://localhost:5601"
ES_URL     = "http://localhost:9200"

HEADERS = {
    "Content-Type":  "application/json",
    "kbn-xsrf":      "true",
}

def req(method, url, data=None):
    body = json.dumps(data).encode() if data else None
    r = urllib.request.Request(url, data=body, headers=HEADERS, method=method)
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        print(f"  HTTP {e.code}: {e.read().decode()[:200]}")
        return None
    except Exception as e:
        print(f"  Erreur: {e}")
        return None

def wait_kibana():
    print("Attente Kibana...")
    for i in range(30):
        try:
            r = urllib.request.urlopen(f"{KIBANA_URL}/api/status", timeout=5)
            data = json.loads(r.read())
            if data.get("status", {}).get("overall", {}).get("level") == "available":
                print("Kibana OK ✓")
                return True
        except:
            pass
        print(f"  tentative {i+1}/30...")
        time.sleep(5)
    return False

def create_index_pattern():
    print("\nCréation index pattern sentinelog-logs...")
    result = req("POST", f"{KIBANA_URL}/api/saved_objects/index-pattern/sentinelog-logs", {
        "attributes": {
            "title":       "sentinelog-logs",
            "timeFieldName": "timestamp"
        }
    })
    if result:
        print("  Index pattern sentinelog-logs créé ✓")

    print("Création index pattern sentinelog-alerts...")
    result = req("POST", f"{KIBANA_URL}/api/saved_objects/index-pattern/sentinelog-alerts", {
        "attributes": {
            "title":       "sentinelog-alerts",
            "timeFieldName": "timestamp"
        }
    })
    if result:
        print("  Index pattern sentinelog-alerts créé ✓")

def set_default_index():
    print("\nDéfinition index par défaut...")
    req("POST", f"{KIBANA_URL}/api/kibana/settings", {
        "changes": {
            "defaultIndex": "sentinelog-logs"
        }
    })
    print("  Index par défaut défini ✓")

def create_visualizations():
    print("\nCréation des visualisations...")

    # Viz 1 : Répartition par sévérité (Donut)
    req("POST", f"{KIBANA_URL}/api/saved_objects/visualization/sentinelog-severity-donut", {
        "attributes": {
            "title": "SentineLog — Répartition par Sévérité",
            "visState": json.dumps({
                "title": "Répartition par Sévérité",
                "type": "pie",
                "params": {
                    "addLegend": True,
                    "addTooltip": True,
                    "isDonut": True,
                    "legendPosition": "right",
                    "type": "pie"
                },
                "aggs": [
                    {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
                    {"id": "2", "enabled": True, "type": "terms", "schema": "segment", "params": {
                        "field": "severity", "size": 10, "order": "desc", "orderBy": "1"
                    }}
                ]
            }),
            "uiStateJSON": "{}",
            "description": "",
            "savedSearchId": None,
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "index": "sentinelog-logs",
                    "query": {"match_all": {}},
                    "filter": []
                })
            }
        }
    })
    print("  Viz Sévérité (donut) ✓")

    # Viz 2 : Timeline logs par heure
    req("POST", f"{KIBANA_URL}/api/saved_objects/visualization/sentinelog-timeline", {
        "attributes": {
            "title": "SentineLog — Timeline des événements",
            "visState": json.dumps({
                "title": "Timeline des événements",
                "type": "histogram",
                "params": {
                    "addLegend": True,
                    "addTimeMarker": False,
                    "addTooltip": True,
                    "defaultYExtents": False,
                    "mode": "stacked",
                    "scale": "linear",
                    "setYExtents": False,
                    "times": [],
                    "type": "histogram"
                },
                "aggs": [
                    {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
                    {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment", "params": {
                        "field": "timestamp", "interval": "auto", "min_doc_count": 1
                    }},
                    {"id": "3", "enabled": True, "type": "terms", "schema": "group", "params": {
                        "field": "severity", "size": 5, "order": "desc", "orderBy": "1"
                    }}
                ]
            }),
            "uiStateJSON": "{}",
            "description": "",
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "index": "sentinelog-logs",
                    "query": {"match_all": {}},
                    "filter": []
                })
            }
        }
    })
    print("  Viz Timeline ✓")

    # Viz 3 : Top IPs
    req("POST", f"{KIBANA_URL}/api/saved_objects/visualization/sentinelog-top-ips", {
        "attributes": {
            "title": "SentineLog — Top 10 IPs suspectes",
            "visState": json.dumps({
                "title": "Top 10 IPs suspectes",
                "type": "table",
                "params": {
                    "perPage": 10,
                    "showMetricsAtAllLevels": False,
                    "showPartialRows": False,
                    "showTotal": False,
                    "sort": {"columnIndex": None, "direction": None}
                },
                "aggs": [
                    {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
                    {"id": "2", "enabled": True, "type": "terms", "schema": "bucket", "params": {
                        "field": "ip", "size": 10, "order": "desc", "orderBy": "1"
                    }}
                ]
            }),
            "uiStateJSON": json.dumps({"vis": {"params": {"sort": {"columnIndex": 1, "direction": "desc"}}}}),
            "description": "",
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "index": "sentinelog-logs",
                    "query": {"terms": {"severity": ["HIGH", "CRITICAL"]}},
                    "filter": []
                })
            }
        }
    })
    print("  Viz Top IPs ✓")

    # Viz 4 : Par catégorie
    req("POST", f"{KIBANA_URL}/api/saved_objects/visualization/sentinelog-categories", {
        "attributes": {
            "title": "SentineLog — Logs par Catégorie",
            "visState": json.dumps({
                "title": "Logs par Catégorie",
                "type": "histogram",
                "params": {
                    "addLegend": True,
                    "addTooltip": True,
                    "mode": "stacked",
                    "type": "histogram"
                },
                "aggs": [
                    {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
                    {"id": "2", "enabled": True, "type": "terms", "schema": "segment", "params": {
                        "field": "category", "size": 10, "order": "desc", "orderBy": "1"
                    }}
                ]
            }),
            "uiStateJSON": "{}",
            "description": "",
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "index": "sentinelog-logs",
                    "query": {"match_all": {}},
                    "filter": []
                })
            }
        }
    })
    print("  Viz Catégories ✓")

def create_saved_searches():
    print("\nCréation des recherches sauvegardées...")

    # Alertes critiques
    req("POST", f"{KIBANA_URL}/api/saved_objects/search/sentinelog-critical-alerts", {
        "attributes": {
            "title": "SentineLog — Alertes CRITICAL",
            "description": "Tous les logs de niveau CRITICAL",
            "hits": 0,
            "columns": ["timestamp", "severity", "category", "ip", "user", "message"],
            "sort": ["timestamp", "desc"],
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "index": "sentinelog-logs",
                    "highlightAll": True,
                    "version": True,
                    "query": {"terms": {"severity": ["CRITICAL"]}},
                    "filter": []
                })
            }
        }
    })
    print("  Search CRITICAL ✓")

    # Brute-force SSH
    req("POST", f"{KIBANA_URL}/api/saved_objects/search/sentinelog-bruteforce", {
        "attributes": {
            "title": "SentineLog — Brute-Force SSH",
            "description": "Tentatives SSH échouées",
            "hits": 0,
            "columns": ["timestamp", "severity", "ip", "user", "message"],
            "sort": ["timestamp", "desc"],
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "index": "sentinelog-logs",
                    "highlightAll": True,
                    "version": True,
                    "query": {"bool": {"must": [
                        {"terms": {"tags": ["brute-force"]}},
                    ]}},
                    "filter": []
                })
            }
        }
    })
    print("  Search Brute-Force ✓")

def create_dashboard():
    print("\nCréation du dashboard principal...")
    req("POST", f"{KIBANA_URL}/api/saved_objects/dashboard/sentinelog-main", {
        "attributes": {
            "title": "SentineLog PRO — Dashboard Principal",
            "description": "Vue d'ensemble du SIEM SentineLog",
            "panelsJSON": json.dumps([
                {
                    "panelIndex": "1",
                    "gridData": {"x": 0, "y": 0, "w": 24, "h": 15, "i": "1"},
                    "id": "sentinelog-timeline",
                    "type": "visualization",
                    "version": "8.12.0"
                },
                {
                    "panelIndex": "2",
                    "gridData": {"x": 24, "y": 0, "w": 24, "h": 15, "i": "2"},
                    "id": "sentinelog-severity-donut",
                    "type": "visualization",
                    "version": "8.12.0"
                },
                {
                    "panelIndex": "3",
                    "gridData": {"x": 0, "y": 15, "w": 24, "h": 15, "i": "3"},
                    "id": "sentinelog-top-ips",
                    "type": "visualization",
                    "version": "8.12.0"
                },
                {
                    "panelIndex": "4",
                    "gridData": {"x": 24, "y": 15, "w": 24, "h": 15, "i": "4"},
                    "id": "sentinelog-categories",
                    "type": "visualization",
                    "version": "8.12.0"
                },
            ]),
            "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}),
            "timeRestore": False,
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({"query": {"match_all": {}}, "filter": []})
            }
        }
    })
    print("  Dashboard principal ✓")

if __name__ == "__main__":
    print("=" * 50)
    print("  SentineLog PRO — Init Kibana")
    print("=" * 50)

    if not wait_kibana():
        print("Kibana non disponible. Arrêt.")
        exit(1)

    create_index_pattern()
    set_default_index()
    create_saved_searches()
    create_visualizations()
    create_dashboard()

    print("\n" + "=" * 50)
    print("  Kibana configuré avec succès ✓")
    print(f"  Dashboard : {KIBANA_URL}/app/dashboards")
    print("=" * 50)
