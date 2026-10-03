# SIEM-IDS Fusion in Splunk

This repository contains reproducibility artefacts for the paper:

SIEM-IDS Fusion in Splunk: DBSCAN-Based De-duplication of Suricata Alerts and Zeek Telemetry

The framework integrates Suricata IDS alerts, Zeek network telemetry, Splunk validation, rule-based correlation, DBSCAN-based de-duplication, and risk-based prioritisation to consolidate high-volume IDS alerts into analyst-facing incident objects.

## Dataset

The experiment uses the CIC-IDS2017 Tuesday PCAP split. The raw CIC-IDS2017 PCAP files are not redistributed in this repository. Please obtain the dataset from the official Canadian Institute for Cybersecurity source.

## Final Environment

- Ubuntu VM
- Suricata 7.0.10
- Zeek 8.2.0
- Splunk Enterprise 9.4.1
- Python virtual environment
- Enabled Suricata alert rules: 51,967
- Correlation time bucket: 60 seconds
- DBSCAN eps: 1.10
- DBSCAN min_samples: 2

## Final Results

| Processing Stage | Count |
|---|---:|
| Raw Suricata alerts | 1,729,794 |
| Operational noise flagged | 1,727,921 |
| Meaningful/non-noise alerts retained | 1,873 |
| Rule-based correlated groups | 38,158 |
| DBSCAN de-duplicated incident objects | 338 |
| Zeek telemetry events | 619,872 |

## Priority Distribution

| Priority | Count |
|---|---:|
| Low | 208 |
| Medium | 124 |
| High | 6 |
| Critical | 0 |

## Repository Structure

scripts/               Python processing and figure-generation scripts  
results_summary/       Final CSV summaries and incident outputs  
splunk_ready_final/    JSONL outputs used for Splunk validation  
splunk_searches/       Representative Splunk SPL validation searches  
figures/               Publication figures  
docs/                  Reproducibility notes  

## Reproducibility Notes

This repository does not include raw CIC-IDS2017 PCAP files, Splunk internal files, credentials, VM files, or large raw exports. It provides scripts, summary outputs, JSONL validation artefacts, figures, and reproducibility notes needed to inspect and reproduce the reported workflow.

## Citation

Please cite the associated SINCONF 2026 paper when using this artefact.
