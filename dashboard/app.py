"""
app.py
ZombieShield — Streamlit Dashboard
Run: streamlit run dashboard/app.py
"""

import sys
import json
from pathlib import Path
from datetime import datetime

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

# add project root to path so engine/advisor imports work
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from engine.bootstrap    import run_full_pipeline
from advisor.advisor     import call_claude
from advisor.config      import resolve_api_key

DATA_DIR = ROOT / "data"


def get_claude_api_key() -> str:
    """Sidebar session → Streamlit secrets → .env / environment."""
    session_key = st.session_state.get("anthropic_api_key", "")
    if session_key:
        return session_key.strip()
    try:
        secret = st.secrets.get("ANTHROPIC_API_KEY", "")
        if secret:
            return str(secret).strip()
    except Exception:
        pass
    return resolve_api_key()

# ── page config ───────────────────────────────────────────────────────────────

st.set_page_config(
    page_title = "ZombieShield | Union Bank API Security",
    page_icon  = "🛡️",
    layout     = "wide",
    initial_sidebar_state = "expanded",
)

# ── custom CSS ────────────────────────────────────────────────────────────────

st.markdown("""
<style>
  [data-testid="stMetricValue"]  { font-size: 2rem !important; font-weight: 700 !important; }
  .risk-critical { color: #dc2626; font-weight: 700; }
  .risk-high     { color: #ea580c; font-weight: 600; }
  .risk-medium   { color: #ca8a04; font-weight: 500; }
  .risk-low      { color: #16a34a; }
  .tag-zombie    { background:#fef2f2; color:#991b1b; padding:2px 8px; border-radius:4px; font-size:12px; font-weight:600; }
  .tag-shadow    { background:#faf5ff; color:#6b21a8; padding:2px 8px; border-radius:4px; font-size:12px; font-weight:600; }
  .tag-active    { background:#f0fdf4; color:#166534; padding:2px 8px; border-radius:4px; font-size:12px; font-weight:600; }
  .tag-borderline{ background:#fffbeb; color:#92400e; padding:2px 8px; border-radius:4px; font-size:12px; font-weight:600; }
  .playbook-step { background:#f8fafc; border-left:3px solid #3b82f6; padding:8px 12px; margin:6px 0; border-radius:0 6px 6px 0; }
  .stDataFrame   { border: 1px solid #e2e8f0; border-radius: 8px; }
  div[data-testid="column"] > div { height: 100%; }
</style>
""", unsafe_allow_html=True)

# ── data loader (must be defined before sidebar uses load_data.clear()) ───────

@st.cache_data(ttl=60)
def load_data():
    classified_path = DATA_DIR / "classified_apis.csv"
    drift_path      = DATA_DIR / "drift_report.json"
    account_path    = DATA_DIR / "accountability_report.json"

    ml_report_path = DATA_DIR / "ml_report.json"
    if (
        not classified_path.exists()
        or not drift_path.exists()
        or not account_path.exists()
        or not ml_report_path.exists()
    ):
        run_full_pipeline()

    df = pd.read_csv(classified_path)
    df["risk_score"]   = pd.to_numeric(df["risk_score"], errors="coerce").fillna(0).astype(int)
    df["days_silent"]  = pd.to_numeric(df["days_silent"], errors="coerce").fillna(0).astype(int)
    df["daily_avg_calls"] = pd.to_numeric(df["daily_avg_calls"], errors="coerce").fillna(0).astype(int)
    df["last_called_date"] = pd.to_datetime(df["last_called_date"], errors="coerce")
    for col in ("ml_anomaly_score", "ml_risk_score", "ml_confidence", "ml_rule_agreement"):
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    with open(drift_path, encoding="utf-8") as f:
        drift = json.load(f)
    with open(account_path, encoding="utf-8") as f:
        account = json.load(f)
    ml_report = {}
    if ml_report_path.exists():
        with open(ml_report_path, encoding="utf-8") as f:
            ml_report = json.load(f)

    return df, drift, account, ml_report


# ── sidebar ───────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("### 🏦 Union Bank of India")
    st.markdown("## 🛡️ ZombieShield")
    st.caption("API Security & Governance Platform")
    st.divider()

    if st.button("🔄 Re-run Full Scan", use_container_width=True, type="primary"):
        with st.spinner("Running classification + ML pipeline..."):
            run_full_pipeline()
        load_data.clear()
        st.success("Scan complete!")
        st.rerun()

    st.divider()
    st.markdown("**Claude API Key**")
    claude_key = st.text_input(
        "Anthropic API key",
        type="password",
        placeholder="sk-ant-… or use .env",
        help="Paste key here, or set ANTHROPIC_API_KEY in .env / .streamlit/secrets.toml",
    )
    if claude_key:
        st.session_state["anthropic_api_key"] = claude_key
    elif get_claude_api_key():
        st.caption("✅ Key loaded from environment / secrets")
    else:
        st.caption("No key — rule-based playbooks only")

    st.divider()
    st.markdown("**Filters**")
    filter_classification = st.multiselect(
        "Classification",
        ["Active", "Zombie", "Shadow", "Borderline"],
        default=["Zombie", "Shadow", "Borderline"]
    )
    filter_severity = st.multiselect(
        "Severity",
        ["Critical", "High", "Medium", "Low"],
        default=["Critical", "High", "Medium", "Low"]
    )
    filter_team = st.multiselect("Team", [
        "Core Banking", "Payments", "KYC & Compliance",
        "Loans", "Digital Channels", "Security", "Analytics"
    ])

    st.divider()
    st.caption("iDEA 2.0 — PS9 | Team Kopiko")
    st.caption("K.J. Somaiya College of Engineering")


# ── apply sidebar filters ─────────────────────────────────────────────────────

df_full, drift_data, account_data, ml_report = load_data()

df = df_full.copy()
if filter_classification:
    df = df[df["classification"].isin(filter_classification)]
if filter_severity:
    df = df[df["severity"].isin(filter_severity)]
if filter_team:
    df = df[df["team"].isin(filter_team)]


# ═══════════════════════════════════════════════════════════════════════════════
# TABS
# ═══════════════════════════════════════════════════════════════════════════════

tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "📊 Overview",
    "🗂️ API Registry",
    "🔬 Risk Drill-Down",
    "🤖 ML Insights",
    "✅ Compliance"
])

CLASS_COLOR_MAP = {
    "Active": "#16a34a", "Zombie": "#dc2626",
    "Shadow": "#7c3aed", "Borderline": "#ca8a04",
}


# ─────────────────────────────────────────────────────────────────────────────
# TAB 1 — OVERVIEW
# ─────────────────────────────────────────────────────────────────────────────

with tab1:
    st.markdown("### API Security Overview")
    st.caption(f"Last scan: {datetime.now().strftime('%d %b %Y, %H:%M')} | "
               f"Union Bank Internal API Registry")

    # KPI row
    total     = len(df_full)
    zombies   = len(df_full[df_full["classification"] == "Zombie"])
    shadows   = len(df_full[df_full["classification"] == "Shadow"])
    criticals = len(df_full[df_full["severity"] == "Critical"])
    active    = len(df_full[df_full["classification"] == "Active"])

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total APIs",      total)
    c2.metric("🟢 Active",       active)
    c3.metric("💀 Zombie APIs",  zombies, delta=f"-{zombies} need action", delta_color="inverse")
    c4.metric("👻 Shadow APIs",  shadows, delta=f"-{shadows} undocumented", delta_color="inverse")
    c5.metric("🔴 Critical Risk",criticals, delta="Immediate action", delta_color="inverse")

    st.divider()

    col1, col2 = st.columns(2)

    with col1:
        # classification donut
        counts = (
            df_full["classification"]
            .value_counts()
            .reset_index(name="Count")
            .rename(columns={"index": "Classification", "classification": "Classification"})
        )
        fig = px.pie(counts, values="Count", names="Classification",
                     color="Classification", color_discrete_map=CLASS_COLOR_MAP,
                     hole=0.55, title="API Status Distribution")
        fig.update_layout(height=320, margin=dict(t=40,b=0,l=0,r=0))
        fig.update_traces(textposition="outside", textinfo="percent+label")
        st.plotly_chart(fig, width="stretch")

    with col2:
        # risk score histogram
        fig2 = px.histogram(
            df_full, x="risk_score", nbins=20,
            color_discrete_sequence=["#3b82f6"],
            title="Risk Score Distribution",
            labels={"risk_score": "Risk Score (0–100)", "count": "No. of APIs"}
        )
        fig2.add_vrect(x0=75, x1=100, fillcolor="#dc2626", opacity=0.1,
                       annotation_text="Critical", annotation_position="top left")
        fig2.add_vrect(x0=50, x1=75, fillcolor="#ea580c", opacity=0.08,
                       annotation_text="High", annotation_position="top left")
        fig2.update_layout(height=320, margin=dict(t=40,b=0,l=0,r=0))
        st.plotly_chart(fig2, width="stretch")

    col3, col4 = st.columns(2)

    with col3:
        # auth type breakdown for flagged APIs only
        flagged = df_full[df_full["classification"].isin(["Zombie","Shadow"])]
        auth_counts = (
            flagged["auth_type"]
            .value_counts()
            .reset_index(name="Count")
            .rename(columns={"index": "Auth Type", "auth_type": "Auth Type"})
        )
        fig3 = px.bar(auth_counts, x="Auth Type", y="Count",
                      color="Count", color_continuous_scale="Reds",
                      title="Auth Types in Zombie & Shadow APIs")
        fig3.update_layout(height=280, margin=dict(t=40,b=0,l=0,r=0), showlegend=False)
        st.plotly_chart(fig3, width="stretch")

    with col4:
        # severity by team
        team_sev = df_full[df_full["severity"].isin(["Critical","High"])]\
                   .groupby(["team","severity"]).size().reset_index(name="count")
        fig4 = px.bar(team_sev, x="team", y="count", color="severity",
                      color_discrete_map={"Critical":"#dc2626","High":"#ea580c"},
                      title="Critical & High Severity by Team",
                      labels={"team":"Team","count":"APIs","severity":"Severity"})
        fig4.update_layout(height=280, margin=dict(t=40,b=0,l=0,r=0),
                           xaxis_tickangle=-30)
        st.plotly_chart(fig4, width="stretch")

    # scatter: risk vs days silent
    st.markdown("#### Risk Score vs Days Since Last Call")
    scatter_df = df_full.copy()
    scatter_df["size"] = scatter_df["risk_score"].clip(lower=10)
    fig5 = px.scatter(
        scatter_df, x="days_silent", y="risk_score",
        color="classification", size="size",
        color_discrete_map=CLASS_COLOR_MAP,
        hover_data=["api_id","endpoint","auth_type","team"],
        labels={"days_silent":"Days Silent","risk_score":"Risk Score"},
        title="Each bubble = one API  |  Bigger = higher risk"
    )
    fig5.add_hline(y=75, line_dash="dash", line_color="#dc2626",
                   annotation_text="Critical threshold")
    fig5.add_vline(x=90, line_dash="dash", line_color="#7c3aed",
                   annotation_text="Zombie threshold (90d)")
    fig5.update_layout(height=380, margin=dict(t=40,b=0,l=0,r=0))
    st.plotly_chart(fig5, width="stretch")


# ─────────────────────────────────────────────────────────────────────────────
# TAB 2 — API REGISTRY
# ─────────────────────────────────────────────────────────────────────────────

with tab2:
    st.markdown("### Full API Registry")

    srch = st.text_input("🔍 Search endpoint or API ID", placeholder="e.g. /api/v1/loans or UBI-API-0023")

    display_df = df.copy()
    if srch:
        mask = (
            display_df["endpoint"].str.contains(srch, case=False, na=False) |
            display_df["api_id"].str.contains(srch, case=False, na=False)
        )
        display_df = display_df[mask]

    # colour severity
    def colour_severity(val):
        colours = {
            "Critical": "background-color:#fef2f2; color:#991b1b; font-weight:700",
            "High"    : "background-color:#fff7ed; color:#9a3412; font-weight:600",
            "Medium"  : "background-color:#fffbeb; color:#92400e",
            "Low"     : "background-color:#f0fdf4; color:#166534",
        }
        return colours.get(val, "")

    def colour_classification(val):
        colours = {
            "Zombie"    : "background-color:#fef2f2; color:#991b1b",
            "Shadow"    : "background-color:#faf5ff; color:#6b21a8",
            "Active"    : "background-color:#f0fdf4; color:#166534",
            "Borderline": "background-color:#fffbeb; color:#92400e",
        }
        return colours.get(val, "")

    def colour_risk(val):
        try:
            score = int(val)
        except (TypeError, ValueError):
            return ""
        if score >= 75:
            return "background-color:#fef2f2; color:#991b1b; font-weight:700"
        if score >= 50:
            return "background-color:#fff7ed; color:#9a3412; font-weight:600"
        if score >= 25:
            return "background-color:#fffbeb; color:#92400e"
        return "background-color:#f0fdf4; color:#166534"

    cols_to_show = [
        "api_id", "endpoint", "method", "classification", "severity", "risk_score",
    ]
    if "ml_risk_score" in display_df.columns:
        cols_to_show += ["ml_predicted_class", "ml_risk_score", "ml_anomaly_score"]
    cols_to_show += ["auth_type", "days_silent", "team", "owner_git_user", "recommended_action"]
    show_df = display_df[cols_to_show].rename(columns={
        "api_id"            : "API ID",
        "endpoint"          : "Endpoint",
        "method"            : "Method",
        "classification"    : "Status",
        "severity"          : "Severity",
        "risk_score"        : "Risk",
        "ml_predicted_class": "ML Class",
        "ml_risk_score"     : "ML Risk",
        "ml_anomaly_score"  : "ML Anomaly",
        "auth_type"         : "Auth",
        "days_silent"       : "Days Silent",
        "team"              : "Team",
        "owner_git_user"    : "Owner",
        "recommended_action": "Action",
    })

    styled = show_df.style\
        .map(colour_severity, subset=["Severity"])\
        .map(colour_classification, subset=["Status"])\
        .map(colour_risk, subset=["Risk"])

    st.dataframe(styled, width="stretch", height=500)
    st.caption(f"Showing {len(display_df)} APIs  |  Use sidebar filters to narrow down")

    # download button
    csv_bytes = display_df.to_csv(index=False).encode("utf-8")
    st.download_button("⬇️ Download filtered results as CSV",
                       csv_bytes, "zombieshield_filtered.csv", "text/csv")


# ─────────────────────────────────────────────────────────────────────────────
# TAB 3 — RISK DRILL-DOWN
# ─────────────────────────────────────────────────────────────────────────────

with tab3:
    st.markdown("### API Risk Drill-Down + LLM Remediation Advisor")

    flagged_df = df_full[df_full["classification"].isin(["Zombie","Shadow","Borderline"])]\
                 .sort_values("risk_score", ascending=False)

    if flagged_df.empty:
        st.info("No flagged APIs found. All clear!")
    else:
        api_options = [
            f"{row['api_id']} | {row['classification']} | {row['severity']} | {row['endpoint']}"
            for _, row in flagged_df.iterrows()
        ]
        selected_label = st.selectbox("Select a flagged API to analyse", api_options)
        selected_id    = selected_label.split(" | ")[0]
        api_row        = flagged_df[flagged_df["api_id"] == selected_id].iloc[0].to_dict()

        # profile card
        st.divider()
        col_a, col_b, col_c = st.columns(3)

        sev_color = {
            "Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"
        }.get(api_row["severity"], "⚪")

        col_a.metric("Rule Risk Score", f"{api_row['risk_score']}/100")
        col_b.metric("Severity",       f"{sev_color} {api_row['severity']}")
        col_c.metric("Days Silent",    f"{api_row['days_silent']} days")
        if api_row.get("ml_risk_score") is not None and str(api_row.get("ml_risk_score")) != "nan":
            m1, m2, m3 = st.columns(3)
            m1.metric("ML Risk Score", f"{api_row.get('ml_risk_score', '—')}/100")
            m2.metric("ML Predicted", str(api_row.get("ml_predicted_class", "—")))
            agree = api_row.get("ml_rule_agreement", 0)
            m3.metric("ML ↔ Rules", "Match" if agree == 1 else "Mismatch")

        st.markdown(f"""
| Field | Value |
|---|---|
| **API ID** | `{api_row['api_id']}` |
| **Endpoint** | `{api_row['endpoint']}` |
| **Method** | `{api_row['method']}` |
| **Classification** | `{api_row['classification']}` |
| **ML Anomaly Score** | `{api_row.get('ml_anomaly_score', '—')}` |
| **ML Confidence** | `{api_row.get('ml_confidence', '—')}` |
| **Auth Type** | `{api_row['auth_type']}` |
| **PII Fields** | `{api_row.get('pii_fields_found','none') or 'none'}` |
| **Team** | {api_row['team']} |
| **Owner (Git)** | `{api_row.get('git_author') or api_row['owner_git_user']}` |
| **Last Commit** | {api_row.get('git_last_commit') or api_row['last_modified']} |
| **In Swagger** | {'✅ Yes' if str(api_row['in_swagger']) == '1' else '❌ No (Shadow API)'} |
""")

        st.divider()
        st.markdown("#### 🤖 AI Remediation Playbook")
        st.caption(
            "Claude AI when `ANTHROPIC_API_KEY` is set; otherwise a built-in rule-based playbook"
        )

        if st.button("🔍 Generate Remediation Playbook", type="primary", use_container_width=True):
            with st.spinner("Generating remediation playbook..."):
                playbook = call_claude(api_row, api_key=get_claude_api_key())
            st.session_state["playbook"] = playbook
            st.session_state["playbook_api_id"] = api_row["api_id"]

        playbook = None
        if (
            st.session_state.get("playbook_api_id") == api_row["api_id"]
            and st.session_state.get("playbook")
        ):
            playbook = st.session_state["playbook"]

        if playbook:
            source = playbook.get("source", "unknown")
            source_label = "Claude AI" if source == "claude" else "Rule-based advisor"
            st.success(f"Playbook ready — {source_label}")

            st.markdown(f"**Risk Summary**")
            st.info(playbook.get("risk_summary", "N/A"))

            col_x, col_y = st.columns(2)
            with col_x:
                st.markdown("**Threat Vectors**")
                for threat in playbook.get("threat_vectors", []):
                    st.markdown(f"- {threat}")

            with col_y:
                st.markdown("**Compliance Impact**")
                st.warning(playbook.get("compliance_impact", "N/A"))

            st.markdown(f"**Recommended Action: `{playbook.get('recommended_action','N/A')}`**")
            st.markdown(f"> {playbook.get('action_reason','')}")

            st.markdown("**Remediation Steps**")
            for step in playbook.get("playbook_steps", []):
                st.markdown(f"""<div class='playbook-step'>
                    <b>Step {step.get('step','?')}:</b> {step.get('action','')}
                    &nbsp;|&nbsp; <b>Owner:</b> {step.get('owner','')}
                    &nbsp;|&nbsp; <b>Deadline:</b> {step.get('deadline','')}
                </div>""", unsafe_allow_html=True)

            col_p, col_q = st.columns(2)
            col_p.markdown(f"**Jira Ticket**\n```\n{playbook.get('jira_ticket_summary','')}\n```")
            col_q.metric("Estimated Risk Reduction",
                         playbook.get("estimated_risk_reduction","N/A"))
        else:
            st.info(
                "Click the button above to generate a remediation playbook. "
                "Without `ANTHROPIC_API_KEY`, a rule-based plan is used automatically."
            )

        # git accountability section
        st.divider()
        st.markdown("#### 🔗 Git Accountability")
        acct_apis = account_data.get("flagged_apis", [])
        match = next((a for a in acct_apis if a["api_id"] == api_row["api_id"]), None)
        if match:
            st.markdown(f"""
| Field | Value |
|---|---|
| **Owner** | `{match['owner']}` |
| **Last Commit** | {match['last_commit_date']} |
| **Commit Message** | _{match['last_commit_msg']}_ |
| **File** | `{match['file_path']}` |
| **Jira Ticket** | `{match['jira_ticket']}` |
""")
        else:
            st.markdown(f"Owner: `{api_row.get('owner_git_user','unknown')}`")


# ─────────────────────────────────────────────────────────────────────────────
# TAB 4 — ML INSIGHTS
# ─────────────────────────────────────────────────────────────────────────────

with tab4:
    st.markdown("### Machine Learning Layer")
    st.caption("Random Forest (classification) + Isolation Forest (anomaly detection)")

    if not ml_report:
        st.warning("ML report not found. Click **Re-run Full Scan** in the sidebar.")
    else:
        summary = ml_report.get("summary", {})
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Hold-out accuracy", f"{ml_report.get('holdout_accuracy_pct', 0)}%")
        m2.metric("ML ↔ rule agreement", f"{summary.get('ml_rule_agreement_pct', 0)}%")
        m3.metric("Avg anomaly score", summary.get("avg_ml_anomaly_score", 0))
        m4.metric("ML-only flags", summary.get("flagged_by_ml_only", 0))

        st.divider()
        col_l, col_r = st.columns(2)

        with col_l:
            if "ml_predicted_class" in df_full.columns:
                compare = df_full.groupby(["classification", "ml_predicted_class"]).size().reset_index(name="count")
                fig_ml = px.sunburst(
                    compare,
                    path=["classification", "ml_predicted_class"],
                    values="count",
                    title="Rule vs ML classification overlap",
                )
                fig_ml.update_layout(height=360, margin=dict(t=40, b=0, l=0, r=0))
                st.plotly_chart(fig_ml, width="stretch")

        with col_r:
            if "ml_anomaly_score" in df_full.columns:
                fig_anom = px.histogram(
                    df_full,
                    x="ml_anomaly_score",
                    color="classification",
                    nbins=20,
                    title="ML anomaly score by API status",
                    color_discrete_map=CLASS_COLOR_MAP,
                )
                fig_anom.update_layout(height=360, margin=dict(t=40, b=0, l=0, r=0))
                st.plotly_chart(fig_anom, width="stretch")

        st.markdown("#### APIs where ML disagrees with rules")
        if "ml_rule_agreement" in df_full.columns:
            mismatch = df_full[df_full["ml_rule_agreement"] == 0][
                ["api_id", "endpoint", "classification", "ml_predicted_class",
                 "ml_confidence", "ml_anomaly_score", "ml_risk_score"]
            ].sort_values("ml_anomaly_score", ascending=False)
            st.dataframe(mismatch, width="stretch", hide_index=True)

        with st.expander("Model details"):
            st.json(ml_report)


# ─────────────────────────────────────────────────────────────────────────────
# TAB 5 — COMPLIANCE
# ─────────────────────────────────────────────────────────────────────────────

with tab5:
    st.markdown("### RBI & DPDP Compliance Dashboard")

    total_apis      = len(df_full)
    zombie_count    = len(df_full[df_full["classification"] == "Zombie"])
    shadow_count    = len(df_full[df_full["classification"] == "Shadow"])
    no_auth_count   = len(df_full[df_full["auth_type"] == "none"])
    pii_no_auth     = len(df_full[(df_full["has_pii"].astype(str) == "1") &
                                   (df_full["auth_type"] == "none")])
    undocumented    = shadow_count
    compliance_pct  = round(((total_apis - zombie_count - shadow_count - no_auth_count)
                              / total_apis) * 100, 1)

    # overall score gauge
    fig_gauge = go.Figure(go.Indicator(
        mode  = "gauge+number+delta",
        value = compliance_pct,
        delta = {"reference": 100, "valueformat": ".1f"},
        title = {"text": "Compliance Score (%)"},
        gauge = {
            "axis"  : {"range": [0,100]},
            "bar"   : {"color": "#3b82f6"},
            "steps" : [
                {"range":[0,50],  "color":"#fef2f2"},
                {"range":[50,75], "color":"#fffbeb"},
                {"range":[75,100],"color":"#f0fdf4"},
            ],
            "threshold": {"line":{"color":"#dc2626","width":3},"value":80}
        }
    ))
    fig_gauge.update_layout(height=280, margin=dict(t=30,b=0,l=40,r=40))
    st.plotly_chart(fig_gauge, width="stretch")

    st.divider()

    # compliance checklist
    checks = [
        {
            "regulation": "RBI IT Framework 2023 — Asset Inventory",
            "requirement": "100% accurate real-time inventory of all digital assets",
            "status": "FAIL" if shadow_count > 0 else "PASS",
            "finding": f"{shadow_count} shadow APIs not documented — inventory incomplete",
            "action": "Document or decommission all shadow APIs",
        },
        {
            "regulation": "RBI IT Framework 2023 — Lifecycle Management",
            "requirement": "Deprecated/unused APIs must be formally decommissioned",
            "status": "FAIL" if zombie_count > 0 else "PASS",
            "finding": f"{zombie_count} zombie APIs still active with no recent calls",
            "action": "Raise decommission tickets for all zombie APIs",
        },
        {
            "regulation": "DPDP Act 2023 — Data Minimisation",
            "requirement": "No unnecessary processing of personal data",
            "status": "FAIL" if pii_no_auth > 0 else "PASS",
            "finding": f"{pii_no_auth} APIs expose PII fields without authentication",
            "action": "Immediately block or add auth to PII endpoints",
        },
        {
            "regulation": "OWASP API9:2023 — Improper Inventory Management",
            "requirement": "All APIs must be documented and have defined lifecycle",
            "status": "FAIL" if undocumented > 0 else "PASS",
            "finding": f"{undocumented} undocumented endpoints found in traffic",
            "action": "Add to swagger spec and assign owners",
        },
        {
            "regulation": "OWASP API1:2023 — Broken Object Level Authorization",
            "requirement": "All endpoints must enforce proper authentication",
            "status": "FAIL" if no_auth_count > 0 else "PASS",
            "finding": f"{no_auth_count} APIs have auth_type=none",
            "action": "Enforce minimum JWT or OAuth2 on all endpoints",
        },
        {
            "regulation": "PCI-DSS v4.0 — API Security",
            "requirement": "Payment APIs must not expose sensitive card data without encryption",
            "status": "WARN",
            "finding": "Manual review required — no card data in synthetic dataset",
            "action": "Conduct manual audit of /payments/* endpoints",
        },
    ]

    for chk in checks:
        icon  = "✅" if chk["status"] == "PASS" else ("⚠️" if chk["status"] == "WARN" else "❌")
        color = "green" if chk["status"] == "PASS" else ("orange" if chk["status"] == "WARN" else "red")
        with st.expander(f"{icon} {chk['regulation']} — **{chk['status']}**"):
            col1, col2 = st.columns(2)
            col1.markdown(f"**Requirement:** {chk['requirement']}")
            col1.markdown(f"**Finding:** {chk['finding']}")
            col2.markdown(f"**Recommended Action:** {chk['action']}")

    st.divider()
    st.markdown("#### Drift Report Summary")
    summary = drift_data.get("summary", {})
    d1, d2, d3 = st.columns(3)
    d1.metric("Swagger Documented", summary.get("total_swagger_paths", 0))
    d2.metric("Shadow APIs Found",  summary.get("shadow_apis", 0))
    d3.metric("PII Exposed (Shadow)", summary.get("pii_exposed_shadow_apis", 0))

    st.divider()
    st.markdown("#### Developer Accountability Summary")
    dev_sum = account_data.get("dev_summary", {})
    dev_rows = []
    for dev, info in dev_sum.items():
        dev_rows.append({
            "Developer"  : dev,
            "Total Flagged": info["total_apis"],
            "Zombie"     : info["zombie_count"],
            "Shadow"     : info["shadow_count"],
            "Critical"   : info["critical_count"],
        })
    if dev_rows:
        dev_df = pd.DataFrame(dev_rows).sort_values("Critical", ascending=False)
        st.dataframe(dev_df, width="stretch", hide_index=True)

    st.caption("Note: All data is synthetic. This is a POC for iDEA 2.0. "
               "Not connected to real Union Bank systems.")
