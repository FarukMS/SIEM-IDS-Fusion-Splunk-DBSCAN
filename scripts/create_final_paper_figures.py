import os
import pandas as pd
import matplotlib.pyplot as plt

BASE = os.path.expanduser("~/siem_ids_fusion")
RESULTS = os.path.join(BASE, "results_final")
OUT = os.path.join(BASE, "paper_assets_final", "figures")

os.makedirs(OUT, exist_ok=True)

plt.rcParams.update({
    "figure.figsize": (9, 5),
    "font.size": 11,
    "axes.titlesize": 13,
    "axes.labelsize": 11,
    "xtick.labelsize": 9,
    "ytick.labelsize": 9,
})

# 1. Alert reduction pipeline
eval_df = pd.read_csv(os.path.join(RESULTS, "evaluation_summary.csv"))

pipeline_stages = [
    "Raw Suricata alerts",
    "Rule-based correlated incidents",
    "DBSCAN de-duplicated incidents"
]

pipeline = eval_df[eval_df["stage"].isin(pipeline_stages)].copy()
pipeline["stage"] = pd.Categorical(pipeline["stage"], categories=pipeline_stages, ordered=True)
pipeline = pipeline.sort_values("stage")

plt.figure()
plt.bar(pipeline["stage"], pipeline["count"])
plt.yscale("log")
plt.title("Alert Reduction Pipeline")
plt.ylabel("Count (log scale)")
plt.xticks(rotation=20, ha="right")
plt.tight_layout()
plt.savefig(os.path.join(OUT, "fig1_alert_reduction_pipeline.png"), dpi=300)
plt.savefig(os.path.join(OUT, "fig1_alert_reduction_pipeline.pdf"))
plt.close()

# 2. Priority distribution
priority = pd.read_csv(os.path.join(RESULTS, "priority_distribution.csv"))

priority_order = ["Critical", "High", "Medium", "Low"]
priority["priority"] = pd.Categorical(priority["priority"], categories=priority_order, ordered=True)
priority = priority.sort_values("priority")

plt.figure()
plt.bar(priority["priority"], priority["count"])
plt.title("Priority Distribution of DBSCAN De-duplicated Incidents")
plt.xlabel("Priority")
plt.ylabel("Number of Incidents")
plt.tight_layout()
plt.savefig(os.path.join(OUT, "fig2_priority_distribution.png"), dpi=300)
plt.savefig(os.path.join(OUT, "fig2_priority_distribution.pdf"))
plt.close()

# 3. Zeek telemetry distribution
zeek = pd.read_csv(os.path.join(RESULTS, "zeek_telemetry_normalised.csv"))
zeek_counts = zeek["zeek_log_type"].value_counts().reset_index()
zeek_counts.columns = ["zeek_log_type", "events"]

plt.figure()
plt.bar(zeek_counts["zeek_log_type"], zeek_counts["events"])
plt.title("Zeek Telemetry Distribution")
plt.xlabel("Zeek Log Type")
plt.ylabel("Number of Events")
plt.tight_layout()
plt.savefig(os.path.join(OUT, "fig3_zeek_telemetry_distribution.png"), dpi=300)
plt.savefig(os.path.join(OUT, "fig3_zeek_telemetry_distribution.pdf"))
plt.close()

# 4. Top Suricata signatures
suricata_sig = pd.read_csv(os.path.join(RESULTS, "suricata_alerts_raw.csv"), usecols=["signature", "category", "severity"])
top_sig = (
    suricata_sig
    .groupby(["signature", "category", "severity"], dropna=False)
    .size()
    .reset_index(name="alerts")
    .sort_values("alerts", ascending=False)
    .head(15)
)

plt.figure(figsize=(10, 7))
plt.barh(top_sig["signature"][::-1], top_sig["alerts"][::-1])
plt.xscale("log")
plt.title("Top 15 Suricata Alert Signatures")
plt.xlabel("Number of Alerts (log scale)")
plt.ylabel("Signature")
plt.tight_layout()
plt.savefig(os.path.join(OUT, "fig4_top_suricata_signatures.png"), dpi=300)
plt.savefig(os.path.join(OUT, "fig4_top_suricata_signatures.pdf"))
plt.close()

# 5. Top 20 DBSCAN incidents by risk score
top_inc = pd.read_csv(os.path.join(RESULTS, "top_20_prioritised_incidents.csv"))

plt.figure(figsize=(10, 6))
plt.bar(top_inc["dbscan_incident_id"], top_inc["risk_score"])
plt.title("Top 20 DBSCAN De-duplicated Incidents by Risk Score")
plt.xlabel("Incident ID")
plt.ylabel("Risk Score")
plt.xticks(rotation=60, ha="right")
plt.tight_layout()
plt.savefig(os.path.join(OUT, "fig5_top_incidents_by_risk_score.png"), dpi=300)
plt.savefig(os.path.join(OUT, "fig5_top_incidents_by_risk_score.pdf"))
plt.close()

# 6. Top 20 DBSCAN incidents by Zeek evidence count
top_zeek = top_inc.sort_values("zeek_event_count", ascending=False)

plt.figure(figsize=(10, 6))
plt.bar(top_zeek["dbscan_incident_id"], top_zeek["zeek_event_count"])
plt.title("Top 20 DBSCAN Incidents by Zeek Evidence Count")
plt.xlabel("Incident ID")
plt.ylabel("Zeek Event Count")
plt.xticks(rotation=60, ha="right")
plt.tight_layout()
plt.savefig(os.path.join(OUT, "fig6_top_incidents_by_zeek_evidence.png"), dpi=300)
plt.savefig(os.path.join(OUT, "fig6_top_incidents_by_zeek_evidence.pdf"))
plt.close()

# 7. Noise versus meaningful alerts
noise_rows = eval_df[eval_df["stage"].isin([
    "Operational noise flagged",
    "Meaningful/non-noise alerts retained"
])].copy()

plt.figure()
plt.bar(noise_rows["stage"], noise_rows["count"])
plt.yscale("log")
plt.title("Operational Noise versus Meaningful Alerts")
plt.ylabel("Alert Count (log scale)")
plt.xticks(rotation=20, ha="right")
plt.tight_layout()
plt.savefig(os.path.join(OUT, "fig7_noise_vs_meaningful_alerts.png"), dpi=300)
plt.savefig(os.path.join(OUT, "fig7_noise_vs_meaningful_alerts.pdf"))
plt.close()

print("Final paper figures created in:", OUT)
