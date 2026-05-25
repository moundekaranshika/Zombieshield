"""
ml_scorer.py
ZombieShield — ML risk layer (Random Forest + Isolation Forest)
Trains on classified API features and augments classified_apis.csv.
Run: python engine/ml_scorer.py
"""

import csv
import json
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

DATA_DIR = Path(__file__).parent.parent / "data"
MODEL_PATH = DATA_DIR / "ml_models.joblib"
REPORT_PATH = DATA_DIR / "ml_report.json"

AUTH_ORDER = ["none", "api_key", "basic_auth", "jwt", "oauth2", "mtls"]
CLASS_LABELS = ["Active", "Zombie", "Shadow", "Borderline"]


def _load_classified() -> pd.DataFrame:
    path = DATA_DIR / "classified_apis.csv"
    if not path.exists():
        raise FileNotFoundError("classified_apis.csv missing — run classifier first.")
    return pd.read_csv(path)


def build_features(df: pd.DataFrame) -> tuple[pd.DataFrame, list[str]]:
    """Engineer numeric features for ML models."""
    work = df.copy()
    work["days_silent"] = pd.to_numeric(work["days_silent"], errors="coerce").fillna(0)
    work["daily_avg_calls"] = pd.to_numeric(work["daily_avg_calls"], errors="coerce").fillna(0)
    work["has_pii"] = pd.to_numeric(work["has_pii"], errors="coerce").fillna(0).astype(int)
    work["in_swagger"] = pd.to_numeric(work["in_swagger"], errors="coerce").fillna(0).astype(int)
    work["deprecated_flag"] = pd.to_numeric(work["deprecated_flag"], errors="coerce").fillna(0).astype(int)
    work["risk_score"] = pd.to_numeric(work.get("risk_score", 0), errors="coerce").fillna(0)
    work["num_data_fields"] = work["data_fields"].fillna("").apply(
        lambda x: len([f for f in str(x).split("|") if f])
    )

    work["auth_rank"] = work["auth_type"].map(
        {a: i for i, a in enumerate(AUTH_ORDER)}
    ).fillna(len(AUTH_ORDER))

    for col in ("method", "environment", "team"):
        le = LabelEncoder()
        work[f"{col}_code"] = le.fit_transform(work[col].astype(str))

    feature_cols = [
        "days_silent",
        "daily_avg_calls",
        "has_pii",
        "in_swagger",
        "deprecated_flag",
        "num_data_fields",
        "auth_rank",
        "method_code",
        "environment_code",
        "team_code",
    ]
    return work, feature_cols


def run_ml_scoring() -> dict:
    print("ZombieShield ML Scorer")
    print("=" * 50)

    df = _load_classified()
    work, feature_cols = build_features(df)
    X = work[feature_cols].to_numpy(dtype=float)
    y = work["classification"].to_numpy()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    clf = RandomForestClassifier(
        n_estimators=120,
        max_depth=12,
        random_state=42,
        class_weight="balanced",
    )
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    accuracy = round(accuracy_score(y_test, y_pred) * 100, 1)

    proba = clf.predict_proba(X)
    classes = list(clf.classes_)
    pred_all = clf.predict(X)
    confidence = proba.max(axis=1)

    iso = IsolationForest(
        n_estimators=100,
        contamination=0.15,
        random_state=42,
    )
    iso.fit(X)
    raw_scores = -iso.decision_function(X)
    min_s, max_s = raw_scores.min(), raw_scores.max()
    if max_s > min_s:
        anomaly_0_100 = ((raw_scores - min_s) / (max_s - min_s) * 100).round(1)
    else:
        anomaly_0_100 = np.zeros(len(raw_scores))

    rule_risk = work["risk_score"].to_numpy(dtype=float)
    ml_risk = np.clip(
        anomaly_0_100 * 0.5 + confidence * 100 * 0.3 + rule_risk * 0.2,
        0,
        100,
    ).round(1)

    agreement = (pred_all == y).astype(int)

    out_df = df.copy()
    out_df["ml_predicted_class"] = pred_all
    out_df["ml_confidence"] = confidence.round(3)
    out_df["ml_anomaly_score"] = anomaly_0_100
    out_df["ml_risk_score"] = ml_risk
    out_df["ml_rule_agreement"] = agreement

    out_path = DATA_DIR / "classified_apis.csv"
    out_df.to_csv(out_path, index=False)

    joblib.dump(
        {
            "classifier": clf,
            "isolation_forest": iso,
            "feature_cols": feature_cols,
            "class_labels": classes,
        },
        MODEL_PATH,
    )

    report = {
        "generated_at": datetime.now().isoformat(),
        "model": "RandomForestClassifier + IsolationForest",
        "features": feature_cols,
        "holdout_accuracy_pct": accuracy,
        "classification_report": classification_report(y_test, y_pred, output_dict=True),
        "summary": {
            "total_apis": len(out_df),
            "ml_rule_agreement_pct": round(agreement.mean() * 100, 1),
            "avg_ml_anomaly_score": round(float(anomaly_0_100.mean()), 1),
            "avg_ml_confidence": round(float(confidence.mean()), 3),
            "flagged_by_ml_only": int(
                ((anomaly_0_100 >= 70) & (work["classification"] == "Active")).sum()
            ),
        },
    }
    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"\n  Hold-out accuracy     : {accuracy}%")
    print(f"  ML ↔ rule agreement   : {report['summary']['ml_rule_agreement_pct']}%")
    print(f"  Avg anomaly score     : {report['summary']['avg_ml_anomaly_score']}")
    print(f"  Models saved          : {MODEL_PATH}")
    print(f"  Updated               : {out_path}")
    return report


if __name__ == "__main__":
    run_ml_scoring()
