"""
advisor.py
ZombieShield — LLM Remediation Advisor
Calls Claude API to generate a remediation playbook for a flagged API.
Falls back to rule-based recommendations when no API key is set or the call fails.
"""

import json
import re
import urllib.request
import urllib.error

from advisor.config import resolve_api_key


MODEL   = "claude-sonnet-4-20250514"
API_URL = "https://api.anthropic.com/v1/messages"


def build_prompt(api: dict) -> str:
    """Build a structured prompt from an API record."""
    return f"""You are a senior cybersecurity engineer at Union Bank of India.
Analyse this flagged API and produce a structured remediation playbook.

API DETAILS:
- API ID       : {api.get('api_id', 'N/A')}
- Endpoint     : {api.get('endpoint', 'N/A')}
- Method       : {api.get('method', 'N/A')}
- Classification: {api.get('classification', 'N/A')}
- Severity     : {api.get('severity', 'N/A')}
- Risk Score   : {api.get('risk_score', 'N/A')}/100
- ML Risk Score: {api.get('ml_risk_score', 'N/A')}/100
- ML Predicted : {api.get('ml_predicted_class', 'N/A')} (confidence {api.get('ml_confidence', 'N/A')})
- ML Anomaly   : {api.get('ml_anomaly_score', 'N/A')}/100
- Auth Type    : {api.get('auth_type', 'N/A')}
- PII Fields   : {api.get('pii_fields_found') or api.get('data_fields', 'none')}
- Days Silent  : {api.get('days_silent', 'N/A')} days since last call
- In Swagger   : {api.get('in_swagger', 'N/A')}
- Owner        : {api.get('git_author') or api.get('owner_git_user', 'N/A')}
- Team         : {api.get('team', 'N/A')}
- Last Commit  : {api.get('git_last_commit') or api.get('last_modified', 'N/A')}
- Deprecated Flag: {api.get('deprecated_flag', '0')}

Respond ONLY with a JSON object (no markdown, no preamble) with these exact keys:
{{
  "risk_summary": "2-3 sentence plain-English summary of why this API is risky",
  "threat_vectors": ["list", "of", "specific", "attack", "vectors", "relevant", "to", "this", "API"],
  "compliance_impact": "Which RBI/DPDP/OWASP rules this violates and why",
  "recommended_action": "one of: IMMEDIATE_BLOCK | SCHEDULE_DECOMMISSION | AUDIT_AND_DOCUMENT | MONITOR",
  "action_reason": "Why this specific action was chosen",
  "playbook_steps": [
    {{"step": 1, "action": "specific action", "owner": "who does it", "deadline": "e.g. within 24hrs"}},
    {{"step": 2, "action": "specific action", "owner": "who does it", "deadline": "e.g. within 72hrs"}},
    {{"step": 3, "action": "specific action", "owner": "who does it", "deadline": "e.g. within 1 week"}}
  ],
  "jira_ticket_summary": "Ready-to-paste Jira ticket title and 1-line description",
  "estimated_risk_reduction": "e.g. 70% reduction in breach probability after remediation"
}}"""


def _as_int(value, default=0) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _has_pii(api: dict) -> bool:
    pii = api.get("pii_fields_found") or api.get("data_fields") or ""
    return bool(str(pii).strip() and str(pii).lower() not in ("none", "nan"))


def rule_based_playbook(api: dict, note: str = "") -> dict:
    """Deterministic remediation plan used for demos and when Claude is unavailable."""
    classification = api.get("classification", "Unknown")
    severity = api.get("severity", "Medium")
    auth = api.get("auth_type", "unknown")
    risk_score = _as_int(api.get("risk_score"))
    days_silent = _as_int(api.get("days_silent"))
    endpoint = api.get("endpoint", "unknown endpoint")
    owner = api.get("git_author") or api.get("owner_git_user", "API owner")
    team = api.get("team", "Security")
    api_id = api.get("api_id", "UBI-API-????")
    in_swagger = str(api.get("in_swagger", "0")) == "1"
    has_pii = _has_pii(api)

    if classification == "Shadow" and (auth == "none" or (has_pii and severity == "Critical")):
        action = "IMMEDIATE_BLOCK"
        reason = "Undocumented endpoint with weak or missing authentication and sensitive exposure."
    elif classification == "Zombie" and risk_score >= 75:
        action = "IMMEDIATE_BLOCK"
        reason = "High-risk stale endpoint should be blocked while decommission is executed."
    elif classification == "Zombie":
        action = "SCHEDULE_DECOMMISSION"
        reason = f"No traffic for {days_silent} days; formal decommission reduces attack surface."
    elif classification == "Shadow":
        action = "AUDIT_AND_DOCUMENT"
        reason = "Endpoint is active in traffic but missing from the official API inventory."
    elif classification == "Borderline":
        action = "MONITOR"
        reason = "Usage is declining; monitor before escalating to decommission."
    else:
        action = "AUDIT_AND_DOCUMENT"
        reason = "Review endpoint posture and confirm ownership."

    threat_vectors = []
    if auth == "none":
        threat_vectors.append("Unauthenticated access to banking data")
    if not in_swagger:
        threat_vectors.append("Shadow API bypasses security review and inventory controls")
    if classification == "Zombie":
        threat_vectors.append("Forgotten endpoint may retain known vulnerabilities")
    if has_pii:
        threat_vectors.append("Exposure of regulated personal data (Aadhaar/PAN/DOB)")
    if not threat_vectors:
        threat_vectors = ["Misconfiguration", "Unauthorized access", "Compliance gap"]

    compliance = []
    if not in_swagger:
        compliance.append("RBI IT Framework 2023 — incomplete digital asset inventory")
        compliance.append("OWASP API9:2023 — improper inventory management")
    if classification == "Zombie":
        compliance.append("RBI lifecycle management — deprecated APIs still reachable")
    if has_pii and auth == "none":
        compliance.append("DPDP Act 2023 — personal data processed without adequate safeguards")
    if auth == "none":
        compliance.append("OWASP API1:2023 — broken authentication on sensitive endpoints")
    if not compliance:
        compliance.append("General API governance and monitoring requirements")

    risk_summary = (
        f"{classification} API `{endpoint}` has risk score {risk_score}/100 ({severity}). "
        f"Auth={auth}, silent for {days_silent} days."
    )
    if note:
        risk_summary += f" {note}"

    return {
        "risk_summary": risk_summary,
        "threat_vectors": threat_vectors,
        "compliance_impact": "; ".join(compliance),
        "recommended_action": action,
        "action_reason": reason,
        "playbook_steps": [
            {
                "step": 1,
                "action": f"Assign owner {owner} and open ZS ticket for {api_id}",
                "owner": team,
                "deadline": "within 24hrs",
            },
            {
                "step": 2,
                "action": (
                    "Block or restrict traffic at API gateway"
                    if action == "IMMEDIATE_BLOCK"
                    else "Validate logs, consumers, and swagger documentation"
                ),
                "owner": "Security Engineering",
                "deadline": "within 72hrs",
            },
            {
                "step": 3,
                "action": (
                    "Decommission endpoint and remove from gateway"
                    if action in ("IMMEDIATE_BLOCK", "SCHEDULE_DECOMMISSION")
                    else "Update inventory and re-scan in ZombieShield"
                ),
                "owner": owner,
                "deadline": "within 1 week",
            },
        ],
        "jira_ticket_summary": (
            f"[ZombieShield] {action} — {api_id} {endpoint} ({classification}/{severity})"
        ),
        "estimated_risk_reduction": (
            "70–85% reduction after block/decommission"
            if action in ("IMMEDIATE_BLOCK", "SCHEDULE_DECOMMISSION")
            else "40–60% reduction after documentation and auth hardening"
        ),
        "source": "rule_based",
    }


def _parse_llm_json(raw: str) -> dict:
    raw = raw.strip()
    raw = re.sub(r"^```(?:json)?\s*", "", raw)
    raw = re.sub(r"\s*```$", "", raw)
    return json.loads(raw)


def call_claude(api: dict, api_key: str | None = None) -> dict:
    """Return a remediation playbook (Claude when configured, else rule-based)."""
    api_key = resolve_api_key(api_key)
    if not api_key:
        return rule_based_playbook(
            api,
            note="Rule-based advisor (set ANTHROPIC_API_KEY for Claude-powered playbooks).",
        )

    payload = json.dumps({
        "model": MODEL,
        "max_tokens": 1000,
        "messages": [{"role": "user", "content": build_prompt(api)}],
    }).encode("utf-8")

    req = urllib.request.Request(
        API_URL,
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            raw = data["content"][0]["text"]
            playbook = _parse_llm_json(raw)
            playbook["source"] = "claude"
            return playbook
    except (urllib.error.HTTPError, urllib.error.URLError, json.JSONDecodeError, KeyError, IndexError) as exc:
        return rule_based_playbook(api, note=f"Claude unavailable ({exc}); using rule-based fallback.")


if __name__ == "__main__":
    sample_api = {
        "api_id": "UBI-API-0007",
        "endpoint": "/legacy/v1/aadhaar/verify",
        "method": "POST",
        "classification": "Zombie",
        "severity": "Critical",
        "risk_score": "95",
        "auth_type": "none",
        "data_fields": "aadhaar_number|pan_number|dob",
        "pii_fields_found": "aadhaar_number|pan_number|dob",
        "days_silent": "380",
        "in_swagger": "1",
        "git_author": "rohit.verma",
        "team": "KYC & Compliance",
        "git_last_commit": "2024-01-15",
        "deprecated_flag": "1",
    }

    print("Generating remediation playbook...")
    print(json.dumps(call_claude(sample_api), indent=2))
