import re
import socket
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

# ─── RGPD & Security by Design ───────────────────────────────────────────────

def mask_ip(ip: Optional[str]) -> Optional[str]:
    """Pseudonymisation de l'IP pour conformité RGPD (ex: 192.168.1.123 -> 192.168.1.x)"""
    if not ip: return None
    parts = ip.split('.')
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.x"
    return ip

# ─── Moteur de Classification Centralisé (Point 2 - DRY) ─────────────────────

RULES = [
    {"id": "SSH_FAILED_AUTH", "pattern": r"(Failed password|authentication failure|Invalid user)", "severity": "CRITICAL", "score": 90, "category": "auth", "tags": ["brute-force", "ssh"]},
    {"id": "IDS_ALERT", "pattern": r"(suricata|ET SCAN|ET EXPLOIT|GPL ATTACK|EMERGING)", "severity": "CRITICAL", "score": 95, "category": "ids", "tags": ["ids", "suricata", "alert"]},
    {"id": "WEB_ATTACK", "pattern": r"(SQL injection|XSS|sqlmap|union select|<script|\.\.\/|cmd=|exec\()", "severity": "CRITICAL", "score": 95, "category": "web", "tags": ["web-attack", "injection"]},
    {"id": "PRIVILEGE_ESC", "pattern": r"(sudo|su root|privilege escalation|NOPASSWD|setuid)", "severity": "HIGH", "score": 80, "category": "auth", "tags": ["privilege-escalation"]},
    {"id": "FIREWALL_BLOCK", "pattern": r"(\[UFW BLOCK\]|DROP|REJECT|iptables.*DROP)", "severity": "HIGH", "score": 70, "category": "firewall", "tags": ["firewall", "blocked"]},
    {"id": "HTTP_SERVER_ERROR", "pattern": r"(HTTP/\S+ 5\d{2}|error 5\d{2}|Internal Server Error)", "severity": "HIGH", "score": 65, "category": "web", "tags": ["http", "server-error"]},
    {"id": "MALWARE_INDICATOR", "pattern": r"(trojan|malware|ransomware|rootkit|backdoor|C2|command.and.control)", "severity": "CRITICAL", "score": 98, "category": "malware", "tags": ["malware", "threat"]},
    {"id": "HTTP_CLIENT_ERROR", "pattern": r"(HTTP/\S+ 4\d{2}|error 4\d{2}| 404 | 403 | 401 )", "severity": "MEDIUM", "score": 40, "category": "web", "tags": ["http", "client-error"]},
    {"id": "CONN_ISSUE", "pattern": r"(connection refused|connection timeout|ECONNREFUSED|ETIMEDOUT)", "severity": "MEDIUM", "score": 35, "category": "network", "tags": ["connectivity"]},
    {"id": "SYSTEM_ERROR", "pattern": r"(\berror\b|\bfailed\b|\bfailure\b)", "severity": "MEDIUM", "score": 30, "category": "system", "tags": ["error"]},
    {"id": "AUTH_SUCCESS", "pattern": r"(Accepted password|session opened|logged in|login success)", "severity": "LOW", "score": 15, "category": "auth", "tags": ["auth", "success"]},
    {"id": "SYSTEM_WARN", "pattern": r"(\bwarning\b|\bwarn\b)", "severity": "LOW", "score": 20, "category": "system", "tags": ["warning"]},
    {"id": "HTTP_ACCESS", "pattern": r"((GET|POST|PUT|DELETE|HEAD|OPTIONS) /)", "severity": "INFO", "score": 5, "category": "web", "tags": ["http", "access"]},
]

# Pré-compilation des regex pour la performance
for r in RULES:
    r["_regex"] = re.compile(r["pattern"], re.I)

IP_RE   = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
USER_RE = re.compile(r"(?:for(?:\s+invalid)?\s+user\s+|user=)([a-zA-Z0-9_\-\.]+)", re.I)

def classify_log(message: str) -> Dict[str, Any]:
    """Analyse un message et retourne ses métadonnées enrichies."""
    for rule in RULES:
        if rule["_regex"].search(message):
            ip_match   = IP_RE.search(message)
            user_match = USER_RE.search(message)
            return {
                "rule_id":        rule["id"],
                "severity":       rule["severity"],
                "severity_score": rule["score"],
                "category":       rule["category"],
                "tags":           list(rule["tags"]),
                "ip":             ip_match.group(1) if ip_match else None,
                "user":           user_match.group(1) if user_match else None,
            }
    
    # Défaut si aucune règle ne correspond
    ip_match = IP_RE.search(message)
    return {
        "rule_id":        "GENERIC",
        "severity":       "INFO",
        "severity_score": 1,
        "category":       "generic",
        "tags":           [],
        "ip":             ip_match.group(1) if ip_match else None,
        "user":           None,
    }

def enrich_log(message: str, source: str = "api", host: str = None, timestamp: str = None) -> Dict[str, Any]:
    """Enrichit un log brut avec métadonnées et masquage RGPD."""
    classified = classify_log(message)
    ip_full    = classified["ip"]
    
    return {
        "timestamp":       timestamp or datetime.now(timezone.utc).isoformat(),
        "message":         message,
        "source":          source,
        "host":            host or socket.gethostname(),
        "severity":        classified["severity"],
        "severity_score":  classified["severity_score"],
        "category":        classified["category"],
        "tags":            classified["tags"],
        "ip":              ip_full,
        "ip_masked":       mask_ip(ip_full), # Pour RGPD
        "user":            classified["user"],
        "rule_id":         classified["rule_id"],
        "raw":             message,
    }
