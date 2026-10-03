#!/usr/bin/env python3

import os
import glob
import json
import time
import ipaddress
import warnings
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.cluster import DBSCAN

warnings.filterwarnings("ignore")

BASE = os.path.expanduser("~/siem_ids_fusion")
RESULTS = os.path.join(BASE, "results_final")
FIGURES = os.path.join(BASE, "figures_final")
SURICATA_RAW_CSV = os.path.join(RESULTS, "suricata_alerts_raw.csv")
SURICATA_LOGS = os.path.join(BASE, "suricata_logs_final")
ZEEK_LOGS = os.path.join(BASE, "zeek_logs_final")

os.makedirs(RESULTS, exist_ok=True)
os.makedirs(FIGURES, exist_ok=True)

TIME_WINDOW = "60s"

NOISE_PATTERNS = [
    "invalid checksum",
    "unable to match response to request",
    "excessive retransmissions",
    "CLOSEWAIT",
    "FIN out of window",
    "bad window update",
    "wrong direction",
    "gzip decompression failed",
    "invalid response chunk len",
    "AppLayer",
    "STREAM",
    "TCPv4",
    "UDPv4"
]


def ip_to_int(value):
    try:
        return int(ipaddress.ip_address(str(value)))
    except Exception:
        return 0


def label_encode(series):
    s = series.fillna("unknown").astype(str)
    enc = LabelEncoder()
    return enc.fit_transform(s)


def load_suricata_alerts():
    print("[1] Loading Suricata alerts...")

    if os.path.exists(SURICATA_RAW_CSV):
        df = pd.read_csv(SURICATA_RAW_CSV)
    else:
        rows = []
        pattern = os.path.join(SURICATA_LOGS, "Tuesday-small_000[0-1][0-9]*", "eve.json")

        for file_path in glob.glob(pattern):
            chunk = os.path.basename(os.path.dirname(file_path))
            with open(file_path, "r", errors="ignore") as fh:
                for line in fh:
                    try:
                        event = json.loads(line)
                    except Exception:
                        continue

                    if event.get("event_type") != "alert":
                        continue

                    alert = event.get("alert", {})
                    rows.append({
                        "chunk": chunk,
                        "timestamp": event.get("timestamp"),
                        "src_ip": event.get("src_ip"),
                        "dest_ip": event.get("dest_ip"),
                        "src_port": event.get("src_port"),
                        "dest_port": event.get("dest_port"),
                        "proto": event.get("proto"),
                        "signature": alert.get("signature"),
                        "category": alert.get("category"),
                        "severity": alert.get("severity"),
                        "flow_id": event.get("flow_id")
                    })

        df = pd.DataFrame(rows)
        df.to_csv(SURICATA_RAW_CSV, index=False)

    df = df[df["chunk"].astype(str).str.contains(r"Tuesday-small_000(0[0-9]|1[0-9])", regex=True)]
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    df = df.dropna(subset=["timestamp", "src_ip", "dest_ip"])

    df["time_bucket"] = df["timestamp"].dt.floor(TIME_WINDOW)

    df["signature"] = df["signature"].fillna("unknown")
    df["category"] = df["category"].fillna("unknown")
    df["proto"] = df["proto"].fillna("unknown")
    df["src_port"] = pd.to_numeric(df["src_port"], errors="coerce").fillna(-1).astype(int)
    df["dest_port"] = pd.to_numeric(df["dest_port"], errors="coerce").fillna(-1).astype(int)
    df["severity"] = pd.to_numeric(df["severity"], errors="coerce").fillna(3).astype(int)

    noise_regex = "|".join(NOISE_PATTERNS)
    df["is_operational_noise"] = df["signature"].str.contains(
        noise_regex, case=False, na=False, regex=True
    )

    print(f"    Raw Suricata alerts: {len(df):,}")
    print(f"    Unique signatures: {df['signature'].nunique():,}")
    print(f"    Operational noise alerts: {df['is_operational_noise'].sum():,}")

    return df


def parse_zeek_file(file_path, log_type):
    fields = None

    with open(file_path, "r", errors="ignore") as fh:
        for line in fh:
            if line.startswith("#fields"):
                fields = line.strip().split("\t")[1:]
                break

    if not fields:
        return pd.DataFrame()

    try:
        df = pd.read_csv(
            file_path,
            sep="\t",
            comment="#",
            names=fields,
            header=None,
            na_values=["-", "(empty)"],
            low_memory=False
        )
    except Exception:
        return pd.DataFrame()

    if "ts" not in df.columns:
        return pd.DataFrame()

    src_col = "id.orig_h" if "id.orig_h" in df.columns else None
    dst_col = "id.resp_h" if "id.resp_h" in df.columns else None

    if not src_col or not dst_col:
        return pd.DataFrame()

    out = pd.DataFrame()
    out["timestamp"] = pd.to_datetime(pd.to_numeric(df["ts"], errors="coerce"), unit="s", utc=True)
    out["src_ip"] = df[src_col].astype(str)
    out["dest_ip"] = df[dst_col].astype(str)

    if "id.orig_p" in df.columns:
        out["src_port"] = pd.to_numeric(df["id.orig_p"], errors="coerce").fillna(-1).astype(int)
    else:
        out["src_port"] = -1

    if "id.resp_p" in df.columns:
        out["dest_port"] = pd.to_numeric(df["id.resp_p"], errors="coerce").fillna(-1).astype(int)
    else:
        out["dest_port"] = -1

    if "proto" in df.columns:
        out["proto"] = df["proto"].fillna("unknown").astype(str)
    else:
        out["proto"] = "unknown"

    if "service" in df.columns:
        out["service"] = df["service"].fillna(log_type).astype(str)
    else:
        out["service"] = log_type

    out["zeek_log_type"] = log_type
    out["source_tool"] = "Zeek"
    out = out.dropna(subset=["timestamp", "src_ip", "dest_ip"])
    out["time_bucket"] = out["timestamp"].dt.floor(TIME_WINDOW)

    return out


def load_zeek_telemetry():
    print("[2] Loading Zeek telemetry...")

    log_types = ["conn", "dns", "http", "ssl", "weird"]
    frames = []

    for chunk_dir in sorted(glob.glob(os.path.join(ZEEK_LOGS, "Tuesday-small_000[0-1][0-9]*"))):
        for log_type in log_types:
            file_path = os.path.join(chunk_dir, f"{log_type}.log")
            if os.path.exists(file_path):
                parsed = parse_zeek_file(file_path, log_type)
                if not parsed.empty:
                    frames.append(parsed)

    if frames:
        zeek = pd.concat(frames, ignore_index=True)
    else:
        zeek = pd.DataFrame(columns=[
            "timestamp", "src_ip", "dest_ip", "src_port", "dest_port",
            "proto", "service", "zeek_log_type", "source_tool", "time_bucket"
        ])

    print(f"    Zeek telemetry events: {len(zeek):,}")
    if not zeek.empty:
        print("    Zeek log distribution:")
        print(zeek["zeek_log_type"].value_counts().to_string())

    zeek.to_csv(os.path.join(RESULTS, "zeek_telemetry_normalised.csv"), index=False)
    return zeek


def build_rule_based_incidents(suricata, zeek):
    print("[3] Building rule-based correlated incidents...")

    keys = [
        "time_bucket",
        "src_ip",
        "dest_ip",
        "dest_port",
        "proto",
        "signature",
        "category",
        "severity"
    ]

    incidents = (
        suricata
        .groupby(keys, dropna=False)
        .agg(
            first_seen=("timestamp", "min"),
            last_seen=("timestamp", "max"),
            alert_count=("signature", "size"),
            flow_count=("flow_id", "nunique"),
            noise_alerts=("is_operational_noise", "sum")
        )
        .reset_index()
    )

    incidents["noise_ratio"] = incidents["noise_alerts"] / incidents["alert_count"]

    if not zeek.empty:
        zeek_evidence = (
            zeek
            .groupby(["time_bucket", "src_ip", "dest_ip"], dropna=False)
            .agg(
                zeek_event_count=("zeek_log_type", "size"),
                zeek_log_types=("zeek_log_type", lambda x: ";".join(sorted(set(x)))),
                zeek_services=("service", lambda x: ";".join(sorted(set(map(str, x)))))
            )
            .reset_index()
        )

        incidents = incidents.merge(
            zeek_evidence,
            on=["time_bucket", "src_ip", "dest_ip"],
            how="left"
        )
    else:
        incidents["zeek_event_count"] = 0
        incidents["zeek_log_types"] = ""
        incidents["zeek_services"] = ""

    incidents["zeek_event_count"] = incidents["zeek_event_count"].fillna(0).astype(int)
    incidents["zeek_log_types"] = incidents["zeek_log_types"].fillna("")
    incidents["zeek_services"] = incidents["zeek_services"].fillna("")
    incidents["telemetry_source_count"] = 1 + (incidents["zeek_event_count"] > 0).astype(int)

    incidents.to_csv(os.path.join(RESULTS, "rule_based_correlated_incidents.csv"), index=False)

    print(f"    Rule-based incident groups: {len(incidents):,}")
    print(f"    Incidents with Zeek evidence: {(incidents['zeek_event_count'] > 0).sum():,}")

    return incidents


def run_dbscan_deduplication(incidents):
    print("[4] Running AI-assisted de-duplication with DBSCAN...")

    work = incidents.copy()
    work = work.reset_index(drop=True)

    work["src_ip_num"] = work["src_ip"].apply(ip_to_int)
    work["dest_ip_num"] = work["dest_ip"].apply(ip_to_int)
    work["proto_enc"] = label_encode(work["proto"])
    work["category_enc"] = label_encode(work["category"])

    work["time_num"] = work["time_bucket"].astype("int64") // 10**9
    work["log_alert_count"] = np.log1p(work["alert_count"])
    work["log_zeek_count"] = np.log1p(work["zeek_event_count"])

    feature_cols = [
        "time_num",
        "src_ip_num",
        "dest_ip_num",
        "dest_port",
        "proto_enc",
        "category_enc",
        "severity",
        "log_alert_count",
        "log_zeek_count",
        "telemetry_source_count"
    ]

    work["dbscan_incident_id"] = None
    incident_counter = 0

    for signature, group in work.groupby("signature"):
        idx = group.index

        if len(idx) == 1:
            work.loc[idx, "dbscan_incident_id"] = f"DBSCAN_{incident_counter}"
            incident_counter += 1
            continue

        X = work.loc[idx, feature_cols].replace([np.inf, -np.inf], 0).fillna(0)
        X_scaled = StandardScaler().fit_transform(X)

        model = DBSCAN(eps=1.10, min_samples=2)
        labels = model.fit_predict(X_scaled)

        for label in sorted(set(labels)):
            members = idx[labels == label]

            if label == -1:
                for row_idx in members:
                    work.loc[row_idx, "dbscan_incident_id"] = f"DBSCAN_{incident_counter}"
                    incident_counter += 1
            else:
                work.loc[members, "dbscan_incident_id"] = f"DBSCAN_{incident_counter}"
                incident_counter += 1

    dedup = (
        work
        .groupby("dbscan_incident_id", dropna=False)
        .agg(
            first_seen=("first_seen", "min"),
            last_seen=("last_seen", "max"),
            src_ip=("src_ip", "first"),
            dest_ip=("dest_ip", "first"),
            dest_port=("dest_port", "first"),
            proto=("proto", "first"),
            signatures=("signature", lambda x: ";".join(sorted(set(map(str, x))))),
            categories=("category", lambda x: ";".join(sorted(set(map(str, x))))),
            min_severity=("severity", "min"),
            raw_alerts=("alert_count", "sum"),
            rule_groups=("alert_count", "count"),
            noise_alerts=("noise_alerts", "sum"),
            zeek_event_count=("zeek_event_count", "sum"),
            telemetry_source_count=("telemetry_source_count", "max"),
            zeek_log_types=("zeek_log_types", lambda x: ";".join(sorted(set(";".join(map(str, x)).split(";")))).strip(";"))
        )
        .reset_index()
    )

    dedup["noise_ratio"] = dedup["noise_alerts"] / dedup["raw_alerts"]

    max_alerts = max(dedup["raw_alerts"].max(), 1)
    max_zeek = max(dedup["zeek_event_count"].max(), 1)

    severity_score = ((4 - dedup["min_severity"]).clip(lower=0, upper=3) / 3) * 35
    frequency_score = (np.log1p(dedup["raw_alerts"]) / np.log1p(max_alerts)) * 30
    zeek_score = (np.log1p(dedup["zeek_event_count"]) / np.log1p(max_zeek)) * 20
    source_score = (dedup["telemetry_source_count"] - 1) * 10

    dedup["risk_score"] = severity_score + frequency_score + zeek_score + source_score

    # Parser/checksum artefacts should not become critical just because they are frequent.
    dedup.loc[dedup["noise_ratio"] >= 0.80, "risk_score"] = np.minimum(
        dedup.loc[dedup["noise_ratio"] >= 0.80, "risk_score"],
        25
    )

    dedup["risk_score"] = dedup["risk_score"].clip(0, 100).round(2)

    dedup["priority"] = pd.cut(
        dedup["risk_score"],
        bins=[-1, 30, 55, 75, 100],
        labels=["Low", "Medium", "High", "Critical"]
    )

    dedup = dedup.sort_values(["risk_score", "raw_alerts"], ascending=False)

    work.to_csv(os.path.join(RESULTS, "dbscan_rule_groups_labeled.csv"), index=False)
    dedup.to_csv(os.path.join(RESULTS, "dbscan_deduplicated_incidents.csv"), index=False)

    print(f"    DBSCAN de-duplicated incidents: {len(dedup):,}")
    print("    Priority distribution:")
    print(dedup["priority"].value_counts().to_string())

    return dedup


def create_evaluation_summary(suricata, rule_incidents, dedup_incidents, zeek):
    print("[5] Creating evaluation summary...")

    raw_alerts = len(suricata)
    operational_noise = int(suricata["is_operational_noise"].sum())
    meaningful_alerts = raw_alerts - operational_noise
    rule_count = len(rule_incidents)
    dbscan_count = len(dedup_incidents)
    zeek_count = len(zeek)

    summary = pd.DataFrame([
        {
            "stage": "Raw Suricata alerts",
            "count": raw_alerts,
            "reduction_from_raw_percent": 0.00
        },
        {
            "stage": "Operational noise flagged",
            "count": operational_noise,
            "reduction_from_raw_percent": round((operational_noise / raw_alerts) * 100, 2)
        },
        {
            "stage": "Meaningful/non-noise alerts retained",
            "count": meaningful_alerts,
            "reduction_from_raw_percent": round((1 - meaningful_alerts / raw_alerts) * 100, 2)
        },
        {
            "stage": "Rule-based correlated incidents",
            "count": rule_count,
            "reduction_from_raw_percent": round((1 - rule_count / raw_alerts) * 100, 2)
        },
        {
            "stage": "DBSCAN de-duplicated incidents",
            "count": dbscan_count,
            "reduction_from_raw_percent": round((1 - dbscan_count / raw_alerts) * 100, 2)
        },
        {
            "stage": "Zeek telemetry events",
            "count": zeek_count,
            "reduction_from_raw_percent": None
        }
    ])

    summary.to_csv(os.path.join(RESULTS, "evaluation_summary.csv"), index=False)

    top_incidents = dedup_incidents.head(20)
    top_incidents.to_csv(os.path.join(RESULTS, "top_20_prioritised_incidents.csv"), index=False)

    priority_summary = (
        dedup_incidents["priority"]
        .value_counts()
        .rename_axis("priority")
        .reset_index(name="count")
    )
    priority_summary.to_csv(os.path.join(RESULTS, "priority_distribution.csv"), index=False)

    print(summary.to_string(index=False))
    return summary


def create_figures(summary, dedup_incidents, suricata):
    print("[6] Creating figures...")

    plot_summary = summary[summary["stage"].isin([
        "Raw Suricata alerts",
        "Rule-based correlated incidents",
        "DBSCAN de-duplicated incidents"
    ])]

    plt.figure(figsize=(8, 5))
    plt.bar(plot_summary["stage"], plot_summary["count"])
    plt.ylabel("Count")
    plt.title("Alert Reduction Across Operational Management Stages")
    plt.xticks(rotation=20, ha="right")
    plt.tight_layout()
    plt.savefig(os.path.join(FIGURES, "alert_reduction_pipeline.png"), dpi=300)
    plt.close()

    top_sig = (
        suricata["signature"]
        .value_counts()
        .head(10)
        .reset_index()
    )
    top_sig.columns = ["signature", "count"]

    plt.figure(figsize=(9, 5))
    plt.barh(top_sig["signature"], top_sig["count"])
    plt.xlabel("Alert Count")
    plt.title("Top Suricata Alert Signatures")
    plt.gca().invert_yaxis()
    plt.tight_layout()
    plt.savefig(os.path.join(FIGURES, "top_suricata_signatures.png"), dpi=300)
    plt.close()

    pr = dedup_incidents["priority"].value_counts().reindex(
        ["Critical", "High", "Medium", "Low"]
    ).fillna(0)

    plt.figure(figsize=(7, 5))
    plt.bar(pr.index.astype(str), pr.values)
    plt.ylabel("Number of Incidents")
    plt.title("Prioritised Incident Distribution")
    plt.tight_layout()
    plt.savefig(os.path.join(FIGURES, "incident_priority_distribution.png"), dpi=300)
    plt.close()

    print(f"    Figures saved to: {FIGURES}")


def main():
    start = time.time()

    suricata = load_suricata_alerts()
    zeek = load_zeek_telemetry()
    rule_incidents = build_rule_based_incidents(suricata, zeek)
    dedup_incidents = run_dbscan_deduplication(rule_incidents)
    summary = create_evaluation_summary(suricata, rule_incidents, dedup_incidents, zeek)
    create_figures(summary, dedup_incidents, suricata)

    runtime = time.time() - start
    with open(os.path.join(RESULTS, "pipeline_runtime.txt"), "w") as f:
        f.write(f"Normalisation, correlation, de-duplication and prioritisation runtime: {runtime:.2f} seconds\n")

    print("\nDONE.")
    print(f"Total pipeline runtime: {runtime:.2f} seconds")
    print(f"Results folder: {RESULTS}")
    print(f"Figures folder: {FIGURES}")


if __name__ == "__main__":
    main()
