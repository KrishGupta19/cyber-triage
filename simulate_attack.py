import requests
import time
import json

BASE_URL = "http://localhost:8000"

def test_health():
    print("Checking if Cyber Triage dashboard is running...")
    try:
        res = requests.get(f"{BASE_URL}/health")
        if res.status_code == 200:
            print("✅ Dashboard is online.")
            return True
    except requests.exceptions.ConnectionError:
        print("❌ Dashboard is offline. Please start it first (e.g., python src/dashboard.py)")
        return False

def trigger_attack():
    print("\n🚀 Injecting simulated crypt0miner.elf attack...")
    res = requests.post(f"{BASE_URL}/api/inject-test-anomaly")
    if res.status_code == 200:
        data = res.json()
        print("✅ Attack injected successfully and detected!")
        print(f"  -> Flagged PID: {data['flagged_pid']}")
        print(f"  -> Process: {data['flagged_process']}")
        print(f"  -> Anomaly Score: {data['anomaly_score']} (Threshold Exceeded: {data['threshold_exceeded']})")
        print(f"  -> Blockchain TX ID: {data['blockchain_tx']}")
        print(f"  -> Forensic Hash: {data['forensic_hash']}")
        return True
    else:
        print(f"❌ Failed to inject attack: {res.text}")
        return False

def verify_reports():
    print("\n📄 Verifying forensic reports...")
    res = requests.get(f"{BASE_URL}/api/anomalies")
    if res.status_code == 200:
        data = res.json()
        print(f"✅ Found {data['count']} total forensic reports on the server.")
    else:
        print("❌ Failed to fetch reports.")

if __name__ == "__main__":
    if test_health():
        time.sleep(1)
        trigger_attack()
        time.sleep(1)
        verify_reports()