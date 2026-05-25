"""
git_mapper.py
ZombieShield — Git Accountability Mapper
Maps each flagged API to its original developer using Git commit history.
Run: python engine/git_mapper.py
"""

import csv
import json
from pathlib import Path
from collections import defaultdict

DATA_DIR = Path(__file__).parent.parent / "data"


def load_git_log():
    with open(DATA_DIR / "git_log.csv") as f:
        return list(csv.DictReader(f))


def load_classified():
    path = DATA_DIR / "classified_apis.csv"
    if not path.exists():
        print("[!] classified_apis.csv not found. Run classifier.py first.")
        return []
    with open(path) as f:
        return list(csv.DictReader(f))


def build_accountability_report():
    print("ZombieShield Git Accountability Mapper")
    print("=" * 50)

    git_log    = load_git_log()
    classified = load_classified()

    # index git log by endpoint
    git_by_endpoint = defaultdict(list)
    for entry in git_log:
        git_by_endpoint[entry["api_endpoint"]].append(entry)

    # build per-developer accountability summary
    dev_summary = defaultdict(lambda: {
        "total_apis"     : 0,
        "zombie_count"   : 0,
        "shadow_count"   : 0,
        "critical_count" : 0,
        "apis"           : []
    })

    flagged_apis = []
    for api in classified:
        if api["classification"] in ("Zombie", "Shadow", "Borderline"):
            owner  = api["git_author"] or api["owner_git_user"]
            commits = git_by_endpoint.get(api["endpoint"], [])
            last_commit = commits[0] if commits else {}

            record = {
                "api_id"           : api["api_id"],
                "endpoint"         : api["endpoint"],
                "classification"   : api["classification"],
                "severity"         : api["severity"],
                "risk_score"       : api["risk_score"],
                "owner"            : owner,
                "last_commit_date" : last_commit.get("date", api["last_modified"]),
                "last_commit_msg"  : last_commit.get("message", "unknown"),
                "commit_hash"      : last_commit.get("commit_hash", "unknown"),
                "file_path"        : last_commit.get("file_path", "unknown"),
                "team"             : api["team"],
                "recommended_action": api["recommended_action"],
                "days_silent"      : api["days_silent"],
                "jira_ticket"      : f"ZS-{api['api_id'].split('-')[-1]}",
            }
            flagged_apis.append(record)

            dev_summary[owner]["total_apis"]   += 1
            dev_summary[owner]["apis"].append(record)
            if api["classification"] == "Zombie":
                dev_summary[owner]["zombie_count"] += 1
            if api["classification"] == "Shadow":
                dev_summary[owner]["shadow_count"] += 1
            if api["severity"] == "Critical":
                dev_summary[owner]["critical_count"] += 1

    # ── print report ──────────────────────────────────────────────────────────
    print(f"\n  Flagged APIs requiring ownership resolution: {len(flagged_apis)}")
    print(f"\n  Developer accountability breakdown:")
    for dev, info in sorted(dev_summary.items(), key=lambda x: -x[1]["critical_count"]):
        print(f"    {dev:<25}  APIs={info['total_apis']}  "
              f"Zombie={info['zombie_count']}  Shadow={info['shadow_count']}  "
              f"Critical={info['critical_count']}")

    # ── write output ──────────────────────────────────────────────────────────
    report = {
        "flagged_apis"   : flagged_apis,
        "dev_summary"    : {k: {**v, "apis": []} for k, v in dev_summary.items()},
    }

    out_path = DATA_DIR / "accountability_report.json"
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2, default=str)

    print(f"\n  Accountability report written: {out_path}")
    return report


if __name__ == "__main__":
    build_accountability_report()
