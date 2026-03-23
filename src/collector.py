import psutil
import json
import time
import os

def collect_processes():
    """Captures live system process data."""
    processes = []
    for proc in psutil.process_iter(['pid', 'ppid', 'name', 'cpu_percent', 'memory_percent']):
        try:
            # Capturing core process telemetry
            info = proc.info.copy()
            try:
                info['username'] = proc.username()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                info['username'] = 'SYSTEM'
            processes.append(info)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return processes

def save_telemetry(data, file_path='data/gnn_baseline_data.json'):
    """Serializes telemetry data to JSON."""
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=4)
    print(f"Captured {len(data)} processes to {file_path}")

if __name__ == "__main__":
    print("Starting Cyber Triage Data Collector...")
    while True:
        try:
            telemetry = collect_processes()
            save_telemetry(telemetry)
            # Sampling frequency as per report requirements
            time.sleep(5) 
        except KeyboardInterrupt:
            print("\nCollector stopped.")
            break
