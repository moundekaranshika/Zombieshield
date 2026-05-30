# ZombieShield — Zombie API Discovery & Defence for Cyber Security

> iDEA 2.0 | PSBs Hackathon Series 2026 | PS9 — Zombie API Discovery for Cyber Security |
> Team Kopiko | Indian Institute of Technology Patna

---

## Problem Statement

Union Bank of India manages hundreds of internal APIs across core banking, payments, KYC, and digital channels.
Over time, APIs are deprecated or abandoned but never formally decommissioned — these become **Zombie APIs**.
Others are deployed without being documented — these are **Shadow APIs**.
Both represent serious cybersecurity risks:

- **Zombie APIs** remain active but unmonitored — attackers can exploit known vulnerabilities in old API versions
- **Shadow APIs** bypass security reviews — they may expose PII (Aadhaar, PAN) with no authentication
- The 2022 **Optus breach** leaked 10 million records via a single unauthenticated deprecated API endpoint

ZombieShield automatically discovers, classifies, scores, and generates AI-powered remediation plans for all risky APIs.

---

## Live Demo

🔗 **Live App:** https://zombieshield-wtk7rx8vvkj6tztvnwyvf7.streamlit.app/

🎥 **Demo Video (D2):** [YouTube link — add before submission]

📄 **Pitch Video (D5):** [YouTube link — add before submission]

---

## What ZombieShield Does

```
API Logs + Swagger Spec
         ↓
  Classification Engine  →  Active / Zombie / Shadow / Borderline
         ↓
    Risk Scoring         →  0–100 score (auth + PII + activity)
         ↓
  Drift Detection        →  Swagger vs live traffic comparison
         ↓
  Git Accountability     →  Maps each flagged API to its developer
         ↓
  LLM Remediation Advisor →  Claude AI generates playbook per API
         ↓
  ML Scoring Layer       →  Random Forest + Isolation Forest
         ↓
  Streamlit Dashboard    →  5 tabs: Overview / Registry / Drill-Down / ML / Compliance
```

---

## Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| Data Generation | Python 3.11, csv, json | Synthetic API registry, swagger spec, git log |
| Classification | Pure Python (rule-based) | Zombie/Shadow/Borderline/Active tagging |
| ML Layer | scikit-learn (RF + Isolation Forest) | Class prediction, anomaly score, ML risk |
| Risk Scoring | Weighted formula | Auth type + PII sensitivity + activity score |
| Drift Detection | Python, JSON diff | Swagger spec vs live traffic comparison |
| Git Accountability | Python, CSV parsing | Maps endpoints to developer commit history |
| LLM Advisor | Claude API (claude-sonnet) | AI-generated remediation playbooks |
| Dashboard | Streamlit, Plotly, Pandas | 5-tab interactive UI |
| Deployment | Streamlit Cloud (free) | Zero-cost public hosting |

**Production upgrade path (not in POC):**
- Data ingestion: eBPF / Zeek / Apache Kafka (real-time traffic)
- Classification: Graph Neural Networks (GraphSAGE)
- Database: Neo4j + PostgreSQL
- Infra: Docker + Kubernetes, on-premise

---

## How to Run Locally

**Prerequisites:** Python 3.9+

```bash
git clone https://github.com/your-team/zombieshield
cd zombieshield
bash run.sh
```

`run.sh` creates `.venv`, installs `requirements.txt`, runs the full pipeline (data → rules → ML → drift → accountability), and starts the dashboard at [http://localhost:8501](http://localhost:8501).

**Manual run (optional):**

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -c "from engine.bootstrap import run_full_pipeline; run_full_pipeline()"
streamlit run streamlit_app.py
```

**Claude API key (optional):** copy `.env.example` → `.env`, set `ANTHROPIC_API_KEY`, or paste the key in the sidebar. Without it, playbooks use the built-in rule-based advisor.

---


## Project Structure

```
zombieshield/
├── data/
│   ├── generate_data.py        ← Synthetic API registry generator (100 APIs)
│   ├── api_registry.csv        ← Generated: 100 fake bank API entries
│   ├── swagger.json            ← Generated: fake OpenAPI/Swagger spec
│   ├── git_log.csv             ← Generated: fake developer commit history
│   ├── classified_apis.csv     ← Output: APIs with classification + risk scores
│   ├── drift_report.json       ← Output: Swagger vs traffic comparison
│   └── accountability_report.json ← Output: Per-developer flagged API summary
├── engine/
│   ├── classifier.py           ← Core classification + risk scoring engine
│   ├── ml_scorer.py            ← ML classification + anomaly scoring
│   ├── bootstrap.py            ← One-shot full pipeline runner
│   ├── drift_detector.py       ← Swagger drift detection
│   └── git_mapper.py           ← Git accountability mapper
├── advisor/
│   └── advisor.py              ← Claude API LLM remediation advisor
├── dashboard/
│   └── app.py                  ← Streamlit dashboard (5 tabs)
├── .streamlit/
│   ├── config.toml             ← Theme / server config for deploy
│   └── secrets.toml.example    ← Claude API key template (Cloud)
├── streamlit_app.py            ← Deploy entry point (Streamlit Cloud)
├── packages.txt                ← Apt packages for Cloud (empty)
├── requirements.txt
├── run.sh                      ← Local one-click setup + run
├── .env.example
└── README.md
```

---

## Dataset

All data is **100% synthetic**, generated by `data/generate_data.py`.

The dataset simulates **100 Union Bank internal APIs** across:
- 10 developer owners across 7 teams
- API endpoints across banking resources: accounts, KYC, payments, loans, UPI, NEFT, RTGS
- 4 status categories injected: 45 Active, 30 Zombie, 15 Shadow, 10 Borderline
- 6 authentication types: none, api_key, basic_auth, jwt, oauth2, mtls
- Sensitive data fields: Aadhaar number, PAN number, DOB, credit score, account balance

No real bank data was used at any point.

---

## Model / Engine Performance (Synthetic Test Set)

Classification engine (rule-based):
- Zombie detection: 100% precision (rule: last_call > 90 days + in_swagger)
- Shadow detection: 100% precision (rule: not in swagger)
- False positive rate on Active APIs: 0% (rules are deterministic)

Risk scoring correlation with manually-labelled severity:
- Critical threshold (score ≥ 75): correctly captures all auth=none + PII APIs
- High threshold (score ≥ 50): correctly captures moderate auth + PII combinations

Note: Rule-based classification achieves perfect precision on synthetic data by design.
A production system with real traffic would require ML models (GNN/Isolation Forest)
to handle ambiguous cases — this is noted as a planned upgrade.

---

## Known Limitations

1. **Synthetic data only** — no real Union Bank APIs analysed
2. **Rule-based classification** — production needs ML for edge cases
3. **Batch processing** — processes CSV files, not real-time streams (production: Kafka)
4. **No authentication on dashboard** — acceptable for POC, not production
5. **LLM advisor requires API key** — falls back to rule-based if key not set
6. **No actual Jira integration** — Jira ticket numbers are simulated
7. **Swagger diff is static** — production needs live API gateway integration

---

## Regulatory Alignment

| Regulation | Requirement | ZombieShield Coverage |
|---|---|---|
| RBI IT Framework 2023 | 100% accurate asset inventory | API registry + shadow detection |
| DPDP Act 2023 | Data minimisation — no unnecessary PII processing | PII field exposure detection |
| OWASP API9:2023 | Improper inventory management | Full lifecycle classification |
| OWASP API1:2023 | Broken object level authorization | Auth type risk scoring |
| PCI-DSS v4.0 | API security for payment endpoints | Team-level filtering for payments |

---

## Team

| Name | Role | Expertise |
|---|---|---|
| Anshika Moundekar | Lead | API Security & Vulnerability Detection |
| Kanika Shrivastava | Backend | API & Data Processing Systems |
| Shivani | Frontend | Dashboard & User Experience |
| Khushi Yadav | ML/Risk | Anomaly Detection & Risk Modeling |

**Institute:** Indian Institute of Technology Patna   
**Hackathon:** iDEA 2.0 — PSBs Hackathon Series 2026, Union Bank of India

---

## Deliverables Index

| # | Deliverable | Link |
|---|---|---|
| D1 | Problem + Solution Brief | [https://docs.google.com/document/d/1MKnFzHhIvplZPnzEYNY-J_vM32DOHUMPmnVeZd0Qqg0/edit?usp=sharing] |
| D2 | Technical Demo Video (5–10 min) | [add YouTube link] |
| D3 | Technical Architecture Document | [add link] |
| D4 | GitHub Repository (this repo) | https://github.com/moundekaranshika/Zombieshield |
| D5 | Pitch Video (5 min) + Slide Deck | [add YouTube link] |

## Contact
For any queries about this submission:
Team Name: Kopiko
Institute: Indian Institute of Technology Patna
Email: anshimoun@gmail.com
iDEA 2.0 Phase 2 Submission
