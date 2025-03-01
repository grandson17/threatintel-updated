# Security Report: Log-Based Threats, PCAP-Based Threats, and Threat Intelligence Matches

## Date: 1st March 2025

## 1. Introduction  
This report presents the results of a network forensic analysis conducted on a packet capture (PCAP) file. The primary objective was to extract key metadata, identify potential security threats, and correlate findings with multiple threat intelligence sources.

A Python-based approach was used to analyze network traffic, extract files, and check network artifacts against established threat intelligence databases. The intelligence sources used in this analysis include:

- **AbuseIPDB** – A database of reported malicious IPs.
- **OTX AlienVault** – A global threat intelligence platform for tracking IP-based threats.
- **VirusTotal** – A multi-engine malware scanning service for analyzing files.

This report details the findings, highlights potential security risks, and provides recommendations for mitigation.

---

## 2. Scope and Objective  

### Scope  
This analysis focuses on examining a packet capture (PCAP) file to extract relevant network metadata and detect security threats. The assessment includes:

- Identifying **source and destination IP addresses**.
- Analyzing **network protocols used** in the captured traffic.
- Extracting **files transferred over the network** and analyzing them for potential threats.
- Correlating identified network artifacts with **threat intelligence feeds**.

### Objective  
The primary objectives of this analysis are:

1. **Network Analysis**  
   - Extract key metadata, including IPs, protocols, and User-Agent strings.
   - Identify files and generate their **SHA-256 hashes** for verification.

2. **Threat Detection**  
   - Identify **potentially malicious network requests**.
   - Detect **unusual User-Agent strings** that may indicate automated scanning or malicious activity.

3. **Threat Intelligence Correlation**  
   - Compare network artifacts against **AbuseIPDB, OTX AlienVault, and VirusTotal**.
   - Determine whether **any IPs or files are associated with known cyber threats**.

4. **Reporting and Recommendations**  
   - Summarize findings in an organized manner.
   - Provide actionable **security recommendations** based on identified threats.

---

## 3. Findings and Analysis  

### 3.1 Network Metadata Extracted  
During the analysis, various network artifacts were extracted, including source and destination IPs, network protocols, and files transferred over the network. The summary of extracted metadata is provided below:

| Category | Details |
|----------|---------|
| **Total Unique IPs** | 6 |
| **Observed Protocols** | TCP, UDP, HTTP, DNS |
| **Extracted Files** | 3 |
| **Suspicious User-Agent Strings** | None detected |

---

### 3.2 Threat Intelligence Findings  

#### 3.2.1 Suspicious IP Addresses Identified  
While none of the analyzed IPs were flagged as outright malicious by AbuseIPDB, several were reported in **OTX AlienVault** for their association with known cyber threats.

| IP Address | Threat Intelligence Source | Threat Type |
|------------|--------------------------|-------------|
| **64.188.19.241** | OTX AlienVault | Blacklisted, linked to **Remcos RAT** |
| **79.134.225.79** | OTX AlienVault | Associated with **threat intelligence reports** |
| **13.107.42.13** | OTX AlienVault | **Potential attack infrastructure** |
| **13.107.42.12** | OTX AlienVault | Linked to **OilRig APT campaign, Akira Ransomware** |
| **104.223.119.167** | OTX AlienVault | **Remcos RAT Dropper** (linked to malware distribution) |

These IPs are associated with **command and control (C2) servers, malware distribution, and past cyber attacks**. Connections to these addresses could indicate **compromised endpoints or malicious activity** within the network.

**Recommended Actions:**  
- Block these IPs at the **firewall or network security layer**.
- Analyze historical network traffic to determine **past connections to these IPs**.
- Investigate whether any internal systems have exchanged data with these addresses.

---

#### 3.2.2 Malicious Files Detected  
Three files were extracted from network traffic, and their **SHA-256 hashes** were checked against VirusTotal. Two of these files were flagged as **potentially malicious** by multiple security vendors.

| Packet | SHA-256 Hash | VirusTotal Results |
|--------|------------|-------------------|
| **8** | `168c146a3c6c...` | **No detections (59 undetected engines)** |
| **64** | `df6b921e5b13...` | **Flagged by 25 security vendors** |
| **2595** | `a9e4bb0982f8...` | **Flagged by 2 security vendors** |

The file associated with **Packet 64** received a high number of detections (25 vendors flagged it as malicious), indicating a strong likelihood of **malware or a potentially harmful executable**. The file associated with **Packet 2595** had a lower detection rate, but its classification by two vendors suggests it warrants further investigation.

The file associated with **Packet 8** was not flagged as malicious, but given its extraction from potentially suspicious network traffic, it should be examined in a **sandbox environment** to rule out hidden threats.

**Recommended Actions:**  
- **Quarantine the flagged files** to prevent execution.
- **Analyze the files in a controlled sandbox environment** to understand their behavior.
- **Block these hashes in endpoint security systems** to prevent similar files from being executed on other systems.

---

## 4. References: Threat Intelligence Feeds Used  

| Threat Intelligence Source | Purpose |
|----------------------------|---------|
| **[AbuseIPDB](https://www.abuseipdb.com/)** | Checks IPs against a global database of reported malicious activity. |
| **[OTX AlienVault](https://otx.alienvault.com/)** | Provides advanced threat intelligence on IPs, domains, and malware indicators. |
| **[VirusTotal](https://www.virustotal.com/)** | Scans files against multiple security vendors for malware detection. |

These sources were used to **correlate network activity with known threat indicators** and assess potential risks.

---

## 5. Conclusion  
The network analysis identified multiple potential security concerns:

- Several **IPs were flagged in OTX AlienVault** as associated with **malware operations, C2 infrastructure, and APT campaigns**.
- Two **extracted files were identified as malicious** by VirusTotal, with one flagged by 25 different security vendors.
- The network traffic did not exhibit **unusual User-Agent activity**, reducing the likelihood of automated scanning or scripted attacks in this particular dataset.

To mitigate risks, it is recommended that organizations:

- **Block identified malicious IPs** at the firewall and monitor for any further communication attempts.
- **Investigate all hosts that communicated with these flagged IPs** to determine whether any systems have been compromised.
- **Quarantine and analyze extracted files** in a safe, isolated environment to understand their functionality and potential threats.
- **Strengthen network monitoring** to detect and respond to threats proactively.

By implementing these recommendations, organizations can reduce their exposure to known cyber threats and enhance their overall security posture.

---
