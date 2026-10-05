"""Streamlit dashboard for detections stored in SQLite."""

from __future__ import annotations

import os
from pathlib import Path

import pandas as pd
import streamlit as st

from dns_exfil_detect.config import load_config
from dns_exfil_detect.detection.ml import MLClassifier
from dns_exfil_detect.storage.sqlite import SqliteStorage


def _load() -> tuple:
    cfg_path = os.environ.get("DNS_EXFIL_CONFIG")
    cfg = load_config(cfg_path)
    store = SqliteStorage(cfg.sqlite_path)
    dets = pd.DataFrame(store.fetch_detections(limit=5000))
    queries = pd.DataFrame(store.fetch_queries(limit=5000))
    importance = {}
    if cfg.ml.model_path.is_file():
        importance = MLClassifier.load(cfg.ml.model_path).feature_importance()
    store.close()
    return cfg, dets, queries, importance


def main() -> None:
    st.set_page_config(page_title="DNS Exfil Detect", layout="wide")
    st.title("DNS tunneling / exfiltration detections")
    st.caption("Defensive sensor view — rule score and ML probability side by side.")

    cfg, dets, queries, importance = _load()
    st.sidebar.markdown(f"**DB:** `{cfg.sqlite_path}`")
    st.sidebar.markdown(f"**Queries stored:** {0 if queries.empty else len(queries)}")
    st.sidebar.markdown(f"**Detections stored:** {0 if dets.empty else len(dets)}")

    if dets.empty:
        st.info("No detections yet. Run `dns-exfil-detect analyze --pcap ...` first.")
        return

    dets["timestamp"] = pd.to_datetime(dets["timestamp"], utc=True, errors="coerce")
    dets["rule_score"] = pd.to_numeric(dets["rule_score"], errors="coerce")
    dets["ml_score"] = pd.to_numeric(dets["ml_score"], errors="coerce")

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Windows scored", len(dets))
    c2.metric("High / critical", int(dets["risk_level"].isin(["high", "critical"]).sum()))
    c3.metric("Max rule score", f"{dets['rule_score'].max():.2f}")
    ml_max = dets["ml_score"].max()
    c4.metric("Max ML P(tunnel)", "n/a" if pd.isna(ml_max) else f"{ml_max:.2f}")

    st.subheader("Flagged domains over time")
    ts = dets.dropna(subset=["timestamp"]).sort_values("timestamp")
    if not ts.empty:
        chart = ts.set_index("timestamp")[["rule_score", "ml_score"]]
        st.line_chart(chart)

    st.subheader("Risk score distribution")
    dist = pd.DataFrame(
        {
            "rule_score": dets["rule_score"],
            "ml_score": dets["ml_score"],
        }
    )
    st.bar_chart(dist)

    left, right = st.columns(2)
    with left:
        st.subheader("ML feature importance")
        if importance:
            imp = pd.Series(importance).sort_values(ascending=True)
            st.bar_chart(imp)
        else:
            st.caption("Train a model (`dns-exfil-detect train`) to populate this chart.")
    with right:
        st.subheader("Risk levels")
        st.bar_chart(dets["risk_level"].value_counts())

    st.subheader("Drill-down")
    level = st.multiselect(
        "Filter risk level",
        sorted(dets["risk_level"].dropna().unique()),
        default=list(dets["risk_level"].dropna().unique()),
    )
    view = dets[dets["risk_level"].isin(level)] if level else dets
    st.dataframe(
        view[
            [
                "timestamp",
                "src_ip",
                "domain",
                "rule_score",
                "ml_score",
                "risk_level",
                "raw_query_count",
                "reason",
            ]
        ],
        use_container_width=True,
        hide_index=True,
    )

    src = st.selectbox("Raw queries for source IP", options=["(all)"] + sorted(dets["src_ip"].unique().tolist()))
    if not queries.empty:
        qview = queries if src == "(all)" else queries[queries["src_ip"] == src]
        st.dataframe(qview.head(200), use_container_width=True, hide_index=True)


if __name__ == "__main__":
    main()
