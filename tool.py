from scapy.all import *
import requests
import time
from collections import Counter
import pyshark
import os
import hashlib
from tabulate import tabulate  # Install using: pip install tabulate

# === CONFIGURATION ===
PCAP_FILE = "PATH_TO_PCAP_FILE"
OUTPUT_DIR = "PATH_TO_STORE_EXTRACTED_FILES"

# === API KEYS ===
ABUSEIPDB_API_KEY = "YOUR_ABUSEIPDB_API_KEY_HERE"
VIRUSTOTAL_API_KEY = "YOUR_VIRUSTOTAL_API_KEY_HERE"
OTX_API_KEY = "YOUR_OTX_API_KEY_HERE"

# === API ENDPOINTS ===
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VT_FILE_URL = "https://www.virustotal.com/api/v3/files/{}"
OTX_URL = "https://otx.alienvault.com/api/v1/indicators/IPv4/{}/general"

# === HEADERS ===
ABUSEIPDB_HEADERS = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
VT_HEADERS = {"x-apikey": VIRUSTOTAL_API_KEY}
OTX_HEADERS = {"X-OTX-API-KEY": OTX_API_KEY}

# === DATA STRUCTURES ===
src_ips = set()
dst_ips = set()
protocols = Counter()
user_agents = Counter()
unique_ips = set()
malicious_ips = []
malicious_files = []  # Stores (packet_number, truncated_hash, flagged_vendors)
otx_results = {}

# === FUNCTION: CALCULATE SHA-256 HASH ===
def calculate_sha256(file_path):
    """Generate SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    
    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            sha256_hash.update(chunk)
    
    return sha256_hash.hexdigest()

# === FUNCTION: CHECK FILES ON VIRUSTOTAL ===
def check_file_virustotal(packet_number, hash_value):
    """Query VirusTotal for the file hash and log results."""
    url = VT_FILE_URL.format(hash_value)
    try:
        response = requests.get(url, headers=VT_HEADERS)
        if response.status_code == 200:
            result = response.json()
            stats = result["data"]["attributes"]["last_analysis_stats"]
            vendor_results = result["data"]["attributes"]["last_analysis_results"]

            # Extract security vendors that flagged the file
            flagged_vendors = [vendor for vendor, data in vendor_results.items() if data["category"] == "malicious"]

            # Format vendors for readability
            vendor_display = ", ".join(flagged_vendors[:5]) + (" ... and more" if len(flagged_vendors) > 5 else "")

            print(f"VirusTotal Results for Packet {packet_number}, SHA-256: {hash_value} - {stats}")

            if stats.get("malicious", 0) > 0:
                malicious_files.append((packet_number, hash_value[:12] + "...", vendor_display))
    except Exception as e:
        print(f"Error checking file hash on VirusTotal: {e}")
    time.sleep(2)

# === FUNCTION: EXTRACT FILES AND CHECK HASHES ===
def extract_files_and_check(pcap_file, output_dir):
    """Extracts files from PCAP and checks them on VirusTotal."""
    cap = pyshark.FileCapture(pcap_file, display_filter="http || ssl")
    extracted_files = []

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    for packet in cap:
        try:
            if hasattr(packet.http, "file_data"):
                file_name = f"{output_dir}/file_{packet.number}.bin"

                try:
                    file_data = packet.http.file_data.replace(":", "")
                    file_bytes = bytes.fromhex(file_data)
                except ValueError:
                    file_bytes = packet.http.file_data.encode("utf-8", errors="ignore")

                with open(file_name, "wb") as f:
                    f.write(file_bytes)

                # Calculate SHA-256 hash of the extracted file
                sha256_hash = calculate_sha256(file_name)
                extracted_files.append((packet.number, sha256_hash))

                print(f"Extracted: {file_name} | Packet: {packet.number} | SHA-256: {sha256_hash}")

        except AttributeError:
            pass
        except Exception as e:
            print(f"Skipping packet {packet.number}: {e}")

    cap.close()

    for packet_number, hash_value in extracted_files:
        check_file_virustotal(packet_number, hash_value)

# === FUNCTION: CHECK IP ON ABUSEIPDB ===
def check_ip_abuseipdb(ip):
    """Query AbuseIPDB to check if an IP is reported as malicious."""
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    try:
        response = requests.get(ABUSEIPDB_URL, headers=ABUSEIPDB_HEADERS, params=params)
        if response.status_code == 200:
            data = response.json()
            abuse_score = data["data"]["abuseConfidenceScore"]
            reports = data["data"]["totalReports"]
            if abuse_score > 0:
                malicious_ips.append(ip)
                print(f"[AbuseIPDB] ⚠️ Malicious IP detected: {ip} (Score: {abuse_score}, Reports: {reports})")
            else:
                print(f"[AbuseIPDB] ✅ IP {ip} is clean.")
    except Exception as e:
        print(f"Error checking IP {ip} on AbuseIPDB: {e}")
    time.sleep(2)

# === FUNCTION: CHECK IP ON OTX ALIENVAULT ===
def check_ip_otx(ip):
    """Query OTX AlienVault for threat intelligence on an IP."""
    try:
        response = requests.get(OTX_URL.format(ip), headers=OTX_HEADERS)
        if response.status_code == 200:
            data = response.json()
            if "pulse_info" in data and data["pulse_info"]["count"] > 0:
                pulses = [pulse["name"] for pulse in data["pulse_info"]["pulses"]]

                # Format threat pulses to avoid table overflow
                pulse_display = ", ".join(pulses[:3]) + (" ... and more" if len(pulses) > 3 else "")

                otx_results[ip] = pulse_display
                print(f"[OTX] ⚠️ Threat intelligence found for {ip}: {pulse_display}")
    except Exception as e:
        print(f"Error checking OTX for {ip}: {e}")
    time.sleep(2)

# === RUN PCAP ANALYSIS ===
packets = rdpcap(PCAP_FILE)
for pkt in packets:
    if IP in pkt:
        src_ips.add(pkt[IP].src)
        dst_ips.add(pkt[IP].dst)
        unique_ips.add(pkt[IP].src)
        unique_ips.add(pkt[IP].dst)

# Scan all unique IPs
for ip in unique_ips:
    print(f"Checking IP: {ip}")
    check_ip_abuseipdb(ip)
    check_ip_otx(ip)

# Extract files and check hashes
extract_files_and_check(PCAP_FILE, OUTPUT_DIR)

# === DISPLAY SUMMARY ===
def display_summary():
    print("\n🔎  SUMMARY OF ANALYSIS RESULTS  🔍\n")

    print("\n🌐 **Malicious IPs Detected (AbuseIPDB)**")
    print(tabulate([[ip] for ip in malicious_ips], headers=["Malicious IP"], tablefmt="fancy_grid") if malicious_ips else "✅ No malicious IPs detected.")

    print("\n🛡 **OTX Threat Intelligence (IPs)**")
    print(tabulate(otx_results.items(), headers=["IP", "Threat Pulses"], tablefmt="fancy_grid") if otx_results else "✅ No IP threats detected in OTX.")

    print("\n📂 **Malicious Files Detected (VirusTotal)**")
    print(tabulate(malicious_files, headers=["Packet", "SHA-256", "Flagged By"], tablefmt="fancy_grid") if malicious_files else "✅ No malicious files detected.")

# Call the summary function
display_summary()
