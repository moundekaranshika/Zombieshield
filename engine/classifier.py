"""
classifier.py
ZombieShield — API Classification Engine
Classifies APIs as Active / Zombie / Shadow and computes risk scores.
Run: python engine/classifier.py
"""

import csv
import json
from datetime import datetime, timedelta
from pathlib import Path

ZOMBIE_THRESHOLD_DAYS  = 90
BORDERLINE_DAYS        = 30
DATA_DIR               = Path(__file__).parent.parent / "data"


# ── loaders ───────────────────────────────────────────────────────────────────

def load_registry():
    with open(DATA_DIR / "api_registry.csv") as f:
        return list(csv.DictReader(f))


def load_swagger():
    with open(DATA_DIR / "swagger.json") as f:
        return json.load(f)


def load_git_log():
    with open(DATA_DIR / "git_log.csv") as f:
        return list(csv.DictReader(f))


# ── classification rules ──────────────────────────────────────────────────────

def classify(api, swagger_paths):
    endpoint     = api["endpoint"]
    in_swagger   = api["in_swagger"] == "1"
    last_called  = api["last_called_date"]
    daily_calls  = int(api["daily_avg_calls"])

    try:
        last_dt = datetime.strptime(last_called, "%Y-%m-%d")
        days_silent = (datetime.now() - last_dt).days
    except ValueError:
        days_silent = 9999

    # Shadow: present in logs / registry but NOT in swagger
    if not in_swagger:
        return "Shadow", days_silent

    # Zombie: documented, but no calls in 90+ days
    if days_silent >= ZOMBIE_THRESHOLD_DAYS:
        return "Zombie", days_silent

    # Borderline: stale but not quite zombie
    if BORDERLINE_DAYS <= days_silent < ZOMBIE_THRESHOLD_DAYS:
        return "Borderline", days_silent

    # Active
    return "Active", days_silent


# ── risk scoring ──────────────────────────────────────────────────────────────

AUTH_RISK = {
    "none"      : 40,
    "api_key"   : 25,
    "basic_auth": 20,
    "jwt"       : 10,
    "oauth2"    : 5,
    "mtls"      : 0,
}

SENSITIVE_FIELDS = {
    "aadhaar_number", "pan_number", "dob", "credit_score",
    "balance", "account_number", "nominee_details"
}

def compute_risk_score(api, classification, days_silent):
    score  = 0
    detail = {}

    # Auth risk (0–40)
    auth       = api["auth_type"]
    auth_pts   = AUTH_RISK.get(auth, 10)
    score     += auth_pts
    detail["auth_risk"] = auth_pts

    # PII exposure (0–35)
    fields    = set(api["data_fields"].split("|"))
    pii_found = fields & SENSITIVE_FIELDS
    pii_pts   = min(len(pii_found) * 12, 35)
    score    += pii_pts
    detail["pii_risk"]  = pii_pts
    detail["pii_fields"] = list(pii_found)

    # Activity risk (0–25)
    if classification == "Zombie":
        act_pts = 25
    elif classification == "Shadow":
        act_pts = 20
    elif classification == "Borderline":
        act_pts = 10
    else:
        act_pts = max(0, 10 - int(api["daily_avg_calls"]) // 1000)
    score            += act_pts
    detail["activity_risk"] = act_pts

    detail["total"]   = min(score, 100)
    return min(score, 100), detail


# ── severity label ────────────────────────────────────────────────────────────

def severity(risk_score):
    if risk_score >= 75:
        return "Critical"
    elif risk_score >= 50:
        return "High"
    elif risk_score >= 25:
        return "Medium"
    return "Low"


# ── recommended action ────────────────────────────────────────────────────────

def recommend_action(classification, risk_score, days_silent, deprecated):
    if classification == "Shadow":
        return "Immediate audit — undocumented endpoint, document or block"
    if classification == "Zombie" and risk_score >= 75:
        return "Immediate decommission — high-risk stale endpoint"
    if classification == "Zombie":
        return "Schedule decommission — raise Jira ticket, notify owner"
    if classification == "Borderline":
        return "Monitor closely — review with team within 7 days"
    if deprecated == "1":
        return "Remove deprecated flag check — still receiving traffic"
    return "No action needed — healthy endpoint"


# ── git accountability ────────────────────────────────────────────────────────

def build_owner_map(git_log):
    owner_map = {}
    for row in git_log:
        ep = row["api_endpoint"]
        if ep not in owner_map:
            owner_map[ep] = {
                "author"     : row["author"],
                "last_commit": row["date"],
                "message"    : row["message"],
                "file"       : row["file_path"],
            }
    return owner_map


# ── main classification pipeline ─────────────────────────────────────────────

def run_classification():
    print("ZombieShield Classification Engine")
    print("=" * 50)

    registry  = load_registry()
    swagger   = load_swagger()
    git_log   = load_git_log()
    owner_map = build_owner_map(git_log)
    swagger_paths = set(swagger.get("paths", {}).keys())

    results = []
    for api in registry:
        classification, days_silent = classify(api, swagger_paths)
        risk_score, risk_detail     = compute_risk_score(api, classification, days_silent)
        sev                         = severity(risk_score)
        action                      = recommend_action(
            classification, risk_score, days_silent, api.get("deprecated_flag", "0")
        )
        owner_info = owner_map.get(api["endpoint"], {
            "author": api["owner_git_user"],
            "last_commit": api["last_modified"],
            "message": "unknown",
            "file": "unknown",
        })

        result = {
            **api,
            "classification"  : classification,
            "days_silent"     : days_silent,
            "risk_score"      : risk_score,
            "severity"        : sev,
            "recommended_action": action,
            "pii_fields_found": "|".join(risk_detail["pii_fields"]),
            "git_author"      : owner_info["author"],
            "git_last_commit" : owner_info["last_commit"],
            "git_message"     : owner_info["message"],
        }
        results.append(result)

    # write output
    out_path = DATA_DIR / "classified_apis.csv"
    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        writer.writeheader()
        writer.writerows(results)

    # print summary
    from collections import Counter
    counts = Counter(r["classification"] for r in results)
    sevs   = Counter(r["severity"] for r in results)

    print(f"\n  Total APIs     : {len(results)}")
    print(f"  Active         : {counts['Active']}")
    print(f"  Zombie         : {counts['Zombie']}")
    print(f"  Shadow         : {counts['Shadow']}")
    print(f"  Borderline     : {counts['Borderline']}")
    print(f"\n  Critical       : {sevs['Critical']}")
    print(f"  High           : {sevs['High']}")
    print(f"  Medium         : {sevs['Medium']}")
    print(f"  Low            : {sevs['Low']}")
    print(f"\n  Output written : {out_path}")
    return results


if __name__ == "__main__":
    run_classification()
