import subprocess
import time
import sys
import os

def run_project():
    """Starts both the Core Engine and the Dashboard."""
    print("="*60)
    print("CYBER TRIAGE SYSTEM LAUNCHER")
    print("="*60)
    
    # 1. Start Engine (in a separate process)
    print("[Launcher] Starting Core Engine...")
    engine_proc = subprocess.Popen([sys.executable, 'src/main.py'])
    
    # 2. Start Dashboard
    print("[Launcher] Starting Dashboard on http://localhost:8000...")
    dashboard_proc = subprocess.Popen([sys.executable, 'src/dashboard.py'])
    
    try:
        while True:
            time.sleep(1)
            if engine_proc.poll() is not None:
                print("[Launcher] Engine terminated unexpectedly.")
                break
            if dashboard_proc.poll() is not None:
                print("[Launcher] Dashboard terminated unexpectedly.")
                break
    except KeyboardInterrupt:
        print("\n[Launcher] Shutting down Cyber Triage...")
        engine_proc.terminate()
        dashboard_proc.terminate()
        print("[Launcher] All systems offline.")

if __name__ == "__main__":
    run_project()
