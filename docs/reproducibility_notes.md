# Reproducibility Notes

This repository provides the scripts, summary outputs, JSONL validation artefacts, Splunk searches, and figures used for the SIEM-IDS fusion experiment.

The raw CIC-IDS2017 PCAP files are not redistributed. They should be downloaded from the official Canadian Institute for Cybersecurity source.

Final environment:

- Ubuntu VM
- Suricata 7.0.10
- Zeek 8.2.0
- Splunk Enterprise 9.4.1
- Python virtual environment
- Enabled Suricata alert rules: 51,967
- CIC-IDS2017 Tuesday split
- 20 valid PCAP chunks processed
- 1 truncated/corrupted chunk excluded
- 60-second correlation window
- DBSCAN eps = 1.10
- DBSCAN min_samples = 2

The final reported outputs are summary artefacts rather than raw packet captures or full Splunk internal data.
