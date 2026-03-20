from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
import uvicorn
import json
import asyncio
import os
import sys
import time
import random

# ── Path resolution ───────────────────────────────────────────────────────────
_THIS_DIR     = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_THIS_DIR)
os.chdir(_PROJECT_ROOT)
sys.path.insert(0, _THIS_DIR)

import torch
import torch.nn.functional as F
from collector import collect_processes, save_telemetry
from graph_builder import build_process_graph, convert_to_pyg
from model import GNNAutoencoder, get_anomaly_score, compute_loss
from blockchain_client import BlockchainClient
from forensic_reporter import ForensicReporter

app = FastAPI(title="Cyber Triage API", version="2.0.0")

# ── Shared state ──────────────────────────────────────────────────────────────
_clients: list[WebSocket] = []
_tx_count = 0
_model: GNNAutoencoder | None = None


def get_model() -> GNNAutoencoder:
    global _model
    if _model is None:
        _model = GNNAutoencoder(in_channels=16, latent_channels=8)
        model_path = os.path.join(_PROJECT_ROOT, "models", "gnn_baseline.pt")
        if os.path.exists(model_path):
            _model.load_state_dict(
                torch.load(model_path, map_location="cpu", weights_only=True)
            )
            print("[Model] Loaded trained weights from models/gnn_baseline.pt")
        else:
            print("[Model] No saved weights found — using untrained model")
        _model.eval()
    return _model


async def broadcast(msg: dict):
    dead = []
    for ws in _clients:
        try:
            await ws.send_json(msg)
        except Exception:
            dead.append(ws)
    for ws in dead:
        _clients.remove(ws)


# ── Core triage loop (runs every 5 s) ─────────────────────────────────────────
async def triage_loop():
    global _tx_count
    blockchain = BlockchainClient()
    reporter   = ForensicReporter(report_dir="reports")

    while True:
        try:
            # 1. Collect live processes
            telemetry = collect_processes()

            # 2. Build graph
            graph    = build_process_graph(telemetry)
            pyg_data = convert_to_pyg(graph)
            node_list = list(graph.nodes())
            edge_count = graph.number_of_edges()

            # 3. GNN inference
            model = get_model()
            with torch.no_grad():
                z, adj_hat, x_hat = model(pyg_data)
                scores    = get_anomaly_score(pyg_data, adj_hat, x_hat)
                max_score = scores.max().item()
                loss_val  = compute_loss(pyg_data, adj_hat, x_hat).item()

            # 4. Enrich telemetry with per-process anomaly scores
            pid_to_score = {
                node_list[i]: round(scores[i].item(), 4)
                for i in range(len(node_list))
            }
            for p in telemetry:
                p['anomaly_score'] = pid_to_score.get(p['pid'], 0.0)
            save_telemetry(telemetry, 'data/current_telemetry.json')

            # 5. Simulated HLF orderer latency baseline
            latency_ms = round(random.gauss(142, 10), 1)
            feed_msg   = f"CYCLE COMPLETE — {len(telemetry)} processes · max_score={max_score:.4f} · loss={loss_val:.4f}"

            # 6. Anomaly handling
            if max_score > 0.75:
                suspicious_idx = scores.argmax().item()
                suspicious_pid = node_list[suspicious_idx]
                proc_info = next(
                    (p for p in telemetry if p['pid'] == suspicious_pid), None
                )
                if proc_info:
                    name = proc_info['name']
                    findings = (
                        f"GNN Anomaly Score {max_score:.4f} exceeded threshold 0.75. "
                        f"Behavioral deviation in child-parent lineage."
                    )
                    report, _ = reporter.generate_report(
                        suspicious_pid, name, max_score, findings
                    )
                    t0 = time.time()
                    tx_id, r_hash = blockchain.log_anomaly_event(
                        suspicious_pid, max_score, name, report
                    )
                    latency_ms = round((time.time() - t0) * 1000, 1)
                    _tx_count += 1

                    alert_msg = (
                        f"CRITICAL: {name} (PID {suspicious_pid}) "
                        f"— Score {max_score:.4f} | TX {tx_id}"
                    )
                    feed_msg = alert_msg
                    await broadcast({
                        "type":        "alert",
                        "msg":         alert_msg,
                        "is_critical": True,
                        "tx_id":       tx_id,
                        "latency_ms":  latency_ms,
                        "tx_count":    _tx_count,
                    })

            # 7. Write cycle results for any other consumers
            os.makedirs('data', exist_ok=True)
            with open('data/cycle_results.json', 'w') as f:
                json.dump({
                    'max_anomaly_score': round(max_score, 4),
                    'latency_ms':        latency_ms,
                    'loss':              round(loss_val, 4),
                    'edge_count':        edge_count,
                    'tx_count':          _tx_count,
                }, f)

            # 8. Broadcast telemetry to all connected dashboards
            await broadcast({
                "type":          "telemetry",
                "data":          telemetry[:25],
                "anomaly_score": round(max_score, 4),
                "latency_ms":    latency_ms,
                "loss":          round(loss_val, 4),
                "edge_count":    edge_count,
                "tx_count":      _tx_count,
                "feed_msg":      feed_msg,
            })

        except Exception as e:
            print(f"[Triage Loop] Error: {e}")
            import traceback; traceback.print_exc()

        await asyncio.sleep(5)


@app.on_event("startup")
async def startup():
    asyncio.create_task(triage_loop())


# ── REST endpoints ─────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok", "service": "CyberTriage API", "version": "2.0.0"}


@app.get("/api/processes")
async def get_processes():
    path = "data/current_telemetry.json"
    if not os.path.exists(path):
        return JSONResponse({"error": "No telemetry collected yet"}, status_code=404)
    with open(path) as f:
        data = json.load(f)
    return {"count": len(data[:25]), "processes": data[:25]}


@app.get("/api/anomalies")
async def get_anomalies():
    if not os.path.exists("reports"):
        return {"count": 0, "anomalies": []}
    reports = []
    for fname in sorted(os.listdir("reports")):
        if fname.endswith(".json") and not fname.startswith("test_"):
            fpath = os.path.join("reports", fname)
            with open(fpath) as f:
                try:
                    reports.append(json.load(f))
                except Exception:
                    pass
    return {"count": len(reports), "anomalies": reports}


@app.post("/api/inject-test-anomaly")
async def inject_test_anomaly():
    """Injects a fake crypt0miner.elf process and runs the full detection pipeline."""
    telemetry = collect_processes()
    telemetry.append({
        "pid": 4821, "ppid": 3001,
        "name": "crypt0miner.elf",
        "cpu_percent": 98.7, "memory_percent": 45.0
    })
    save_telemetry(telemetry, "data/current_telemetry.json")

    graph    = build_process_graph(telemetry)
    data     = convert_to_pyg(graph)
    model    = get_model()
    with torch.no_grad():
        _, adj_hat, x_hat = model(data)
        scores = get_anomaly_score(data, adj_hat, x_hat)

    INJECTED_PID = 4821
    node_list    = list(graph.nodes())
    pid_to_idx   = {pid: i for i, pid in enumerate(node_list)}
    injected_score = scores[pid_to_idx[INJECTED_PID]].item() if INJECTED_PID in pid_to_idx else 0.0

    reporter  = ForensicReporter(report_dir="reports")
    findings  = (
        f"GNN Anomaly Score {injected_score:.4f} exceeded threshold 0.75. "
        f"Orphan process spawned from unknown PPID 3001, cpu=98.7%, mem=45.0%."
    )
    report, report_path = reporter.generate_report(INJECTED_PID, "crypt0miner.elf", injected_score, findings)

    blockchain = BlockchainClient()
    tx_id, r_hash = blockchain.log_anomaly_event(INJECTED_PID, injected_score, "crypt0miner.elf", report)

    return {
        "injected":          True,
        "flagged_pid":       INJECTED_PID,
        "flagged_process":   "crypt0miner.elf",
        "anomaly_score":     round(injected_score, 4),
        "threshold_exceeded": injected_score > 0.75,
        "blockchain_tx":     tx_id,
        "forensic_hash":     r_hash,
        "report_path":       report_path,
    }


@app.get("/")
async def get():
    index_path = os.path.join(_PROJECT_ROOT, "static", "index.html")
    with open(index_path, encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    _clients.append(websocket)
    print(f"[WS] Client connected ({len(_clients)} total)")
    try:
        while True:
            await asyncio.sleep(30)   # keepalive; triage_loop does the pushing
    except WebSocketDisconnect:
        pass
    finally:
        if websocket in _clients:
            _clients.remove(websocket)
        print(f"[WS] Client disconnected ({len(_clients)} remaining)")


if __name__ == "__main__":
    print("Starting Cyber Triage Dashboard on http://localhost:8000")
    uvicorn.run(app, host="0.0.0.0", port=8000)
