# Threat Intelligence & Automation

## Overview
This project automates **network forensics analysis** on a **packet capture (PCAP) file** by extracting network metadata, identifying potential threats, and correlating findings with multiple **threat intelligence sources**.

### Features:
- Extracts **source & destination IPs, network protocols, and files** from the PCAP.
- Checks **IPs against threat intelligence feeds** (AbuseIPDB & OTX AlienVault).
- Analyzes extracted **files using VirusTotal**.
- Generates a **security report (`security_report.md`)** with findings and recommendations.

---

## Prerequisites

### 1. Install Required Python Packages  
Ensure you have Python installed (`Python 3.8+` recommended). Then install the required dependencies:

```bash
pip install requests scapy pyshark tabulate
