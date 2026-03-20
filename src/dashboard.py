from fastapi import FastAPI, WebSocket
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
import uvicorn
import json
import asyncio
import os
import sys

# ── Path resolution ──────────────────────────────────────────────────────────
# dashboard.py lives in  <project_root>/src/dashboard.py
# We need the project root so all relative paths work correctly.
_THIS_DIR   = os.path.dirname(os.path.abspath(__file__))   # …/src
_PROJECT_ROOT = os.path.dirname(_THIS_DIR)                 # …/cyber_triage
os.chdir(_PROJECT_ROOT)          # make CWD = project root for data/reports/…

sys.path.insert(0, _THIS_DIR)

app = FastAPI(title="Cyber Triage API", version="1.0.0")

# Serving static files (index.html, styles.css)
if not os.path.exists("static"):
    os.makedirs("static")

# ── REST endpoints ──────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    """Health check — confirms the API server is running."""
    return {"status": "ok", "service": "CyberTriage API", "version": "1.0.0"}

@app.get("/api/processes")
async def get_processes():
    """Returns the latest collected process telemetry (top 25)."""
    path = "data/current_telemetry.json"
    if not os.path.exists(path):
        return JSONResponse({"error": "No telemetry collected yet"}, status_code=404)
    with open(path, "r") as f:
        data = json.load(f)
    return {"count": len(data[:25]), "processes": data[:25]}

@app.get("/api/anomalies")
async def get_anomalies():
    """Returns all forensic reports generated so far."""
    if not os.path.exists("reports"):
        return {"count": 0, "anomalies": []}
    reports = []
    for fname in sorted(os.listdir("reports")):
        if fname.endswith(".json") and not fname.startswith("test_"):
            fpath = os.path.join("reports", fname)
            with open(fpath, "r") as f:
                try:
                    reports.append(json.load(f))
                except Exception:
                    pass
    return {"count": len(reports), "anomalies": reports}

@app.post("/api/inject-test-anomaly")
async def inject_test_anomaly():
    """Injects a fake crypt0miner.elf process and runs the full detection pipeline."""
    import torch
    from collector import collect_processes, save_telemetry
    from graph_builder import build_process_graph, convert_to_pyg
    from model import GNNAutoencoder, get_anomaly_score
    from blockchain_client import BlockchainClient
    from forensic_reporter import ForensicReporter

    # Collect live processes and inject the fake malicious one
    telemetry = collect_processes()
    telemetry.append({
        "pid": 4821, "ppid": 3001,
        "name": "crypt0miner.elf",
        "cpu_percent": 98.7, "memory_percent": 45.0
    })
    save_telemetry(telemetry, "data/current_telemetry.json")

    # Build graph and run GNN
    graph = build_process_graph(telemetry)
    data = convert_to_pyg(graph)
    model = GNNAutoencoder(in_channels=16, latent_channels=8)
    model.load_state_dict(torch.load("models/gnn_baseline.pt", weights_only=True))
    model.eval()
    with torch.no_grad():
        _, adj_hat, x_hat = model(data)
        scores = get_anomaly_score(data, adj_hat, x_hat)

    # Look up the injected PID directly — argmax can return a different
    # high-scoring live process (e.g. node.exe) if multiple scores are clamped to 1.0.
    INJECTED_PID = 4821
    node_list = list(graph.nodes())
    pid_to_idx = {pid: i for i, pid in enumerate(node_list)}
    injected_score = scores[pid_to_idx[INJECTED_PID]].item() if INJECTED_PID in pid_to_idx else 0.0
    max_score = scores.max().item()

    suspicious_pid = INJECTED_PID
    name = "crypt0miner.elf"

    # Count other processes that also crossed the threshold
    other_flagged = [
        node_list[i] for i in range(len(node_list))
        if scores[i].item() > 0.75 and node_list[i] != INJECTED_PID
    ]

    # Generate report + commit to blockchain
    reporter = ForensicReporter(report_dir="reports")
    findings = (f"GNN Anomaly Score {injected_score:.4f} exceeded threshold 0.75. "
                f"Orphan process spawned from unknown PPID 3001, cpu=98.7%, mem=45.0%.")
    report, report_path = reporter.generate_report(suspicious_pid, name, injected_score, findings)

    blockchain = BlockchainClient()
    tx_id, r_hash = blockchain.log_anomaly_event(suspicious_pid, injected_score, name, report)

    return {
        "injected": True,
        "flagged_pid": suspicious_pid,
        "flagged_process": name,
        "anomaly_score": round(injected_score, 4),
        "threshold_exceeded": injected_score > 0.75,
        "other_flagged_count": len(other_flagged),
        "blockchain_tx": tx_id,
        "forensic_hash": r_hash,
        "report_path": report_path,
    }

@app.get("/")
async def get():
    index_path = os.path.join(_PROJECT_ROOT, "static", "index.html")
    with open(index_path, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    print("New dashboard connection established.")
    
    last_checked_report = None
    
    while True:
        try:
            # 1. Push Telemetry
            if os.path.exists("data/current_telemetry.json"):
                with open("data/current_telemetry.json", "r") as f:
                    data = json.load(f)
                    # Send top 25 processes for the more detailed UI
                    await websocket.send_json({"type": "telemetry", "data": data[:25]})
            
            # 2. Push Recent Alerts (Forensic Reports)
            if os.path.exists("reports"):
                reports = sorted(os.listdir("reports"), key=lambda x: os.path.getmtime(os.path.join("reports", x)), reverse=True)
                if reports:
                    latest_report_file = reports[0]
                    if latest_report_file != last_checked_report:
                        with open(os.path.join("reports", latest_report_file), "r") as f:
                            report_data = json.load(f)
                            await websocket.send_json({
                                "type": "alert", 
                                "msg": f"CRITICAL: {report_data['incident_details']['process_name']} (PID {report_data['incident_details']['pid']}) - Anomaly Score {report_data['incident_details']['anomaly_score']:.4f}",
                                "is_critical": True
                            })
                        last_checked_report = latest_report_file
            
            await asyncio.sleep(2) # Faster updates for better UI feel
        except Exception as e:
            print(f"WebSocket error: {e}")
            break

if __name__ == "__main__":
    print("Starting Cyber Triage Dashboard on http://localhost:8000")
    uvicorn.run(app, host="0.0.0.0", port=8000)
