import requests
import re
import csv
import time
from collections import defaultdict, Counter

API_KEY = "VirusTotal API KEY"
INPUT_FILE = "hashes.txt"
OUTPUT_FILE = "results.csv"

FAMILY_CATEGORY_MAP = {
    "zbot": "trojan", "njrat": "rat", "remcos": "rat", "agent": "trojan",
    "emotet": "trojan", "formbook": "infostealer", "lokibot": "infostealer",
    "ransom": "ransomware", "locker": "ransomware", "keylogger": "keylogger",
    "darkcomet": "rat", "rootkit": "rootkit", "coinminer": "miner", "xrat": "rat",
    "bladabindi": "rat", "gamarue": "worm", "gandcrab": "ransomware",
    "redline": "infostealer", "azorult": "infostealer", "quakbot": "trojan",
    "dridex": "trojan", "nanocore": "rat", "revenge": "rat", "spyeye": "spyware",
    "xorist": "ransomware", "application":"pua", "html":"phish"
}

ENGINE_PRIORITY = {
    "Microsoft": 100, "Avast":95, "Sophos": 90, "ESET-NOD32": 85, "BitDefender": 80,
    "TrendMicro": 75, "McAfee": 70, "Fortinet": 65, "GData":60, "SentinelOne": 55,
    "ZoneAlarm": 50, "Ikarus": 45, "AVG": 40
}
DEFAULT_PRIORITY = 5

def normalize_name(raw_name):
    name = raw_name.lower()
    name = re.sub(r"(trojan|worm|win32|w32|malware|virus|generic|heur|riskware|unsafe|variant|gen!|application|html|W64|w64)\W*", "", name)
    return name

def infer_category(raw_name):
    name = raw_name.lower()
    for family, category in FAMILY_CATEGORY_MAP.items():
        if family in name:
            return category
    return "trojan"

def query_virustotal(api_key, file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    return None

def analyze_hash(api_key, file_hash):
    data = query_virustotal(api_key, file_hash)
    if not data:
        return {"hash": file_hash, "name": None, "category": None, "confidence": 0}

    results = data["data"]["attributes"]["last_analysis_results"]
    detection_pool = []

    for engine, result in results.items():
        if result["category"] == "malicious" and result["result"]:
            raw_name = result["result"]
            norm_name = normalize_name(raw_name)
            priority = ENGINE_PRIORITY.get(engine, DEFAULT_PRIORITY)
            detection_pool.append((priority, engine, norm_name, raw_name))

    if not detection_pool:
        return {"hash": file_hash, "name": None, "category": None, "confidence": 0}

    detection_pool.sort(reverse=True)
    top_priority, top_engine, norm_name, raw_name = detection_pool[0]
    category = infer_category(raw_name)

    if not norm_name or norm_name == "":
        norm_counter = Counter([n for _, _, n, _ in detection_pool])
        norm_name = norm_counter.most_common(1)[0][0]
        category = infer_category(norm_name)

    final_name = f"{category}/{norm_name}"

    return {
        "hash": file_hash,
        "name": final_name,
        "category": category,
        "confidence": top_priority
    }

def read_hashes_from_file(filename):
    with open(filename, "r") as f:
        return [line.strip() for line in f if line.strip()]

def write_results_to_csv(filename, results):
    with open(filename, mode="w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["hash", "name", "category", "confidence"])
        writer.writeheader()
        for result in results:
            writer.writerow(result)

def analyze_hashes_from_file(api_key, input_file, output_file, delay=15):
    hash_list = read_hashes_from_file(input_file)
    results = []
    for i, h in enumerate(hash_list, 1):
        print(f"[{i}/{len(hash_list)}] Processing: {h}")
        result = analyze_hash(api_key, h)
        results.append(result)
        time.sleep(delay)
    write_results_to_csv(output_file, results)
    print(f"\nDone. Output saved to: {output_file}")

if __name__ == "__main__":
    analyze_hashes_from_file(API_KEY, INPUT_FILE, OUTPUT_FILE)
