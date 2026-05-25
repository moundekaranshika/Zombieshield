"""
drift_detector.py
ZombieShield — Swagger Drift Detector
Compares live API traffic logs against the official Swagger/OpenAPI spec.
Finds: shadow APIs (in logs, not in spec) and zombie candidates (in spec, never called).
Run: python engine/drift_detector.py
"""

import csv
import json
from pathlib import Path
from datetime import datetime

DATA_DIR = Path(__file__).parent.parent / "data"


def load_swagger():
    with open(DATA_DIR / "swagger.json") as f:
        return json.load(f)


def load_registry():
    with open(DATA_DIR / "api_registry.csv") as f:
        return list(csv.DictReader(f))


def detect_drift():
    print("ZombieShield Drift Detector")
    print("=" * 50)

    swagger  = load_swagger()
    registry = load_registry()

    documented = set(swagger.get("paths", {}).keys())
    in_traffic = {r["endpoint"] for r in registry}

    # ── Finding 1: Shadow APIs ────────────────────────────────────────────────
    # APIs seen in traffic/logs but NOT documented in swagger
    shadows = []
    for api in registry:
        if api["endpoint"] not in documented:
            shadows.append({
                "api_id"         : api["api_id"],
                "endpoint"       : api["endpoint"],
                "method"         : api["method"],
                "last_called_date": api["last_called_date"],
                "daily_avg_calls": api["daily_avg_calls"],
                "auth_type"      : api["auth_type"],
                "has_pii"        : api["has_pii"],
                "owner_git_user" : api["owner_git_user"],
                "drift_type"     : "Shadow — in traffic, not in swagger",
                "risk"           : "HIGH — undocumented endpoint, unknown security posture",
            })

    # ── Finding 2: Zombie candidates from swagger ─────────────────────────────
    # APIs documented in swagger but receiving ZERO recent traffic
    zombies_from_swagger = []
    for path, methods in swagger.get("paths", {}).items():
        matched = [r for r in registry if r["endpoint"] == path]
        if not matched:
            # documented in swagger but no registry entry at all
            zombies_from_swagger.append({
                "endpoint"  : path,
                "methods"   : list(methods.keys()),
                "drift_type": "Phantom — in swagger spec, zero traffic records",
                "risk"      : "MEDIUM — may be totally unused, worth reviewing",
            })
        else:
            for r in matched:
                calls = int(r["daily_avg_calls"])
                if calls == 0:
                    try:
                        last_dt = datetime.strptime(r["last_called_date"], "%Y-%m-%d")
                        days_silent = (datetime.now() - last_dt).days
                    except ValueError:
                        days_silent = 9999

                    zombies_from_swagger.append({
                        "api_id"         : r["api_id"],
                        "endpoint"       : path,
                        "last_called_date": r["last_called_date"],
                        "days_silent"    : days_silent,
                        "auth_type"      : r["auth_type"],
                        "owner_git_user" : r["owner_git_user"],
                        "drift_type"     : "Zombie candidate — in swagger, zero calls",
                        "risk"           : "HIGH — active endpoint, no legitimate usage",
                    })

    # ── Finding 3: Undocumented endpoints with PII ────────────────────────────
    pii_shadows = [s for s in shadows if s["has_pii"] == "1"]

    # ── print report ──────────────────────────────────────────────────────────
    print(f"\n  Swagger documented paths    : {len(documented)}")
    print(f"  APIs in traffic logs        : {len(in_traffic)}")
    print(f"\n  Shadow APIs found           : {len(shadows)}")
    print(f"  Zombie candidates (swagger) : {len(zombies_from_swagger)}")
    print(f"  Shadow APIs exposing PII    : {len(pii_shadows)}")

    if shadows:
        print("\n  TOP SHADOW APIs (first 5):")
        for s in shadows[:5]:
            print(f"    [{s['risk'][:4]}] {s['endpoint']}  owner={s['owner_git_user']}")

    if pii_shadows:
        print("\n  ⚠  CRITICAL: Shadow APIs exposing PII:")
        for s in pii_shadows:
            print(f"    {s['endpoint']}  auth={s['auth_type']}  owner={s['owner_git_user']}")

    # ── write drift report ────────────────────────────────────────────────────
    report = {
        "generated_at"          : datetime.now().isoformat(),
        "summary": {
            "total_swagger_paths"       : len(documented),
            "total_traffic_apis"        : len(in_traffic),
            "shadow_apis"               : len(shadows),
            "zombie_candidates"         : len(zombies_from_swagger),
            "pii_exposed_shadow_apis"   : len(pii_shadows),
        },
        "shadow_apis"          : shadows,
        "zombie_candidates"    : zombies_from_swagger,
    }

    out_path = DATA_DIR / "drift_report.json"
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n  Drift report written : {out_path}")
    return report


if __name__ == "__main__":
    detect_drift()
