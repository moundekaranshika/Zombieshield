"""
generate_data.py
ZombieShield — Synthetic API Registry Generator
Generates 100 fake Union Bank API entries with realistic fields.
Run: python data/generate_data.py
"""

import csv
import json
import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(42)

DATA_DIR = Path(__file__).parent

# ── helpers ──────────────────────────────────────────────────────────────────

def days_ago(n):
    return (datetime.now() - timedelta(days=n)).strftime("%Y-%m-%d")

def random_date_between(a, b):
    delta = b - a
    return (a + timedelta(days=random.randint(0, delta.days))).strftime("%Y-%m-%d")

# ── field pools ───────────────────────────────────────────────────────────────

PREFIXES     = ["/api/v1", "/api/v2", "/api/v3", "/legacy/v1", "/internal/v1"]
RESOURCES    = ["accounts", "customers", "loans", "transactions", "payments",
                "kyc", "aadhaar", "pan-verify", "credit-score", "statements",
                "beneficiaries", "neft", "rtgs", "upi", "ifsc", "branch",
                "employees", "audit-logs", "reports", "notifications"]
ACTIONS      = ["list", "get", "create", "update", "delete", "export",
                "verify", "validate", "sync", "fetch", "submit", "approve"]
METHODS      = ["GET", "POST", "PUT", "DELETE", "PATCH"]
AUTH_TYPES   = ["none", "api_key", "oauth2", "jwt", "basic_auth", "mtls"]
DATA_FIELDS  = [
    "account_number", "balance", "customer_id", "name", "email",
    "phone", "aadhaar_number", "pan_number", "dob", "address",
    "transaction_id", "amount", "ifsc_code", "branch_id", "employee_id",
    "credit_score", "loan_amount", "interest_rate", "nominee_details",
    "upi_id"
]
SENSITIVE    = {"aadhaar_number", "pan_number", "dob", "credit_score",
                "balance", "account_number", "nominee_details"}
OWNERS       = ["ananya.sharma", "rohit.verma", "priya.iyer", "deepak.nair",
                "sneha.patel", "arjun.mehta", "kavya.reddy", "vivek.gupta",
                "meera.krishnan", "suresh.bose"]
COMMIT_MSGS  = ["initial commit", "add endpoint", "fix auth bug",
                "update response schema", "deprecation notice added",
                "hotfix prod issue", "merge feature branch", "refactor logic",
                "add rate limiting", "update docs"]
TEAMS        = ["Core Banking", "Payments", "KYC & Compliance",
                "Loans", "Digital Channels", "Security", "Analytics"]
ENVIRONMENTS = ["prod", "prod", "prod", "staging", "dev"]


def make_endpoint(i):
    prefix   = random.choice(PREFIXES)
    resource = random.choice(RESOURCES)
    action   = random.choice(ACTIONS)
    return f"{prefix}/{resource}/{action}"


def make_api(i, status_hint):
    endpoint     = make_endpoint(i)
    method       = random.choice(METHODS)
    auth         = random.choice(AUTH_TYPES)
    fields_count = random.randint(1, 5)
    fields       = random.sample(DATA_FIELDS, fields_count)
    has_pii      = any(f in SENSITIVE for f in fields)
    owner        = random.choice(OWNERS)
    team         = random.choice(TEAMS)
    environment  = random.choice(ENVIRONMENTS)
    commit_msg   = random.choice(COMMIT_MSGS)
    version      = random.choice(["v1", "v2", "v3", "legacy"])

    # last_called_date based on status
    if status_hint == "active":
        last_called = days_ago(random.randint(0, 29))
    elif status_hint == "zombie":
        last_called = days_ago(random.randint(91, 730))
    elif status_hint == "shadow":
        last_called = days_ago(random.randint(1, 60))
    else:
        last_called = days_ago(random.randint(30, 90))

    # shadow APIs are NOT in swagger
    in_swagger = 0 if status_hint == "shadow" else 1

    # created / last_modified
    created_date   = random_date_between(
        datetime.now() - timedelta(days=1800),
        datetime.now() - timedelta(days=400)
    )
    last_modified  = random_date_between(
        datetime.strptime(created_date, "%Y-%m-%d"),
        datetime.now() - timedelta(days=10)
    )

    # call volume
    if status_hint == "zombie":
        daily_calls = 0
    elif status_hint == "shadow":
        daily_calls = random.randint(1, 50)
    else:
        daily_calls = random.randint(100, 10000)

    # risk score
    risk = compute_risk(auth, has_pii, status_hint, daily_calls)

    return {
        "api_id"         : f"UBI-API-{i:04d}",
        "endpoint"       : endpoint,
        "method"         : method,
        "version"        : version,
        "status_hint"    : status_hint,
        "auth_type"      : auth,
        "data_fields"    : "|".join(fields),
        "has_pii"        : int(has_pii),
        "in_swagger"     : in_swagger,
        "last_called_date": last_called,
        "daily_avg_calls": daily_calls,
        "created_date"   : created_date,
        "last_modified"  : last_modified,
        "owner_git_user" : owner,
        "team"           : team,
        "environment"    : environment,
        "last_commit_msg": commit_msg,
        "risk_score"     : risk,
        "deprecated_flag": 1 if status_hint == "zombie" and random.random() > 0.6 else 0,
    }


def compute_risk(auth, has_pii, status_hint, daily_calls):
    score = 0
    # auth risk (40 pts)
    auth_pts = {"none": 40, "api_key": 25, "basic_auth": 20,
                "jwt": 10, "oauth2": 5, "mtls": 0}
    score += auth_pts.get(auth, 10)
    # pii (40 pts)
    score += 40 if has_pii else 0
    # activity (20 pts)
    if status_hint == "zombie":
        score += 20
    elif status_hint == "shadow":
        score += 15
    elif daily_calls < 10:
        score += 10
    return min(score, 100)


# ── generate 100 APIs ─────────────────────────────────────────────────────────

def generate():
    apis = []
    # 45 active, 30 zombie, 15 shadow, 10 borderline
    hints = (["active"] * 45 + ["zombie"] * 30 +
             ["shadow"] * 15 + ["borderline"] * 10)
    random.shuffle(hints)

    for i, hint in enumerate(hints, start=1):
        apis.append(make_api(i, hint))

    # write CSV
    fieldnames = list(apis[0].keys())
    with open(DATA_DIR / "api_registry.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(apis)

    print(f"[✓] Generated {len(apis)} API entries → data/api_registry.csv")
    return apis


# ── generate swagger.json ────────────────────────────────────────────────────

def generate_swagger(apis):
    paths = {}
    for api in apis:
        if api["in_swagger"]:
            ep = api["endpoint"]
            method = api["method"].lower()
            if ep not in paths:
                paths[ep] = {}
            paths[ep][method] = {
                "summary"    : f"Endpoint {api['api_id']}",
                "operationId": api["api_id"],
                "tags"       : [api["team"]],
                "security"   : [{"bearerAuth": []}] if api["auth_type"] not in ("none",) else [],
                "responses"  : {"200": {"description": "Success"}}
            }

    swagger = {
        "openapi": "3.0.0",
        "info"   : {"title": "Union Bank Internal API Spec", "version": "1.0.0"},
        "paths"  : paths
    }
    with open(DATA_DIR / "swagger.json", "w", encoding="utf-8") as f:
        json.dump(swagger, f, indent=2)
    print(f"[✓] Generated swagger.json with {len(paths)} documented paths")


# ── generate git_log.csv ─────────────────────────────────────────────────────

def generate_git_log(apis):
    rows = []
    for api in apis:
        commit_date = random_date_between(
            datetime.strptime(api["last_modified"], "%Y-%m-%d") - timedelta(days=30),
            datetime.strptime(api["last_modified"], "%Y-%m-%d")
        )
        rows.append({
            "commit_hash" : f"a{random.randint(100000,999999)}b",
            "author"      : api["owner_git_user"],
            "date"        : commit_date,
            "message"     : api["last_commit_msg"],
            "file_path"   : f"src/routes{api['endpoint']}.py",
            "api_endpoint": api["endpoint"],
        })

    with open(DATA_DIR / "git_log.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print(f"[✓] Generated git_log.csv with {len(rows)} commit entries")


if __name__ == "__main__":
    apis = generate()
    generate_swagger(apis)
    generate_git_log(apis)
    print("\nAll data files created in data/")
