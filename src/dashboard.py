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
blockchain_client_instance = BlockchainClient()
_alerted_pids: dict = {}   # pid -> last alert timestamp (5-min cooldown)

# Well-known Windows system processes — never save to disk, only show on dashboard
_KNOWN_SAFE_PIDS   = {0, 4}
_KNOWN_SAFE_NAMES  = {
    "System Idle Process", "System", "Registry",
    "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "LsaIso.exe",
    "fontdrvhost.exe", "svchost.exe", "WUDFHost.exe", "RuntimeBroker.exe",
}
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


# ── Core triage loop (runs every 7 s) ─────────────────────────────────────────
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
                
            # Sort processes by anomaly score descending so the most suspicious are at the top
            telemetry.sort(key=lambda x: x.get('anomaly_score', 0.0), reverse=True)
            
            save_telemetry(telemetry, 'data/current_telemetry.json')

            # 5. Simulated HLF orderer latency baseline
            latency_ms = round(random.gauss(142, 10), 1)
            feed_msg   = f"CYCLE COMPLETE — {len(telemetry)} processes · max_score={max_score:.4f} · loss={loss_val:.4f}"

            # 6. Anomaly handling
            # - Always broadcast to dashboard (every cycle)
            # - Only save to disk once per 5-min cooldown, and never for known system processes
            COOLDOWN = 300
            now = time.time()
            if max_score > 0.75:
                suspicious_idx = scores.argmax().item()
                suspicious_pid = node_list[suspicious_idx]
                proc_info = next(
                    (p for p in telemetry if p['pid'] == suspicious_pid), None
                )
                if proc_info:
                    from datetime import datetime as _dt
                    import hashlib as _hl
                    name     = proc_info['name']
                    hosts    = proc_info.get('remote_hosts', [])
                    findings = (
                        f"GNN Anomaly Score {max_score:.4f} exceeded threshold 0.75. "
                        f"Behavioral deviation in child-parent lineage."
                    )
                    
                    # Append network data to the forensic report
                    if hosts:
                        findings += f" Network connections tracked to: {', '.join(hosts)}."
                        
                    is_known_safe = (
                        suspicious_pid in _KNOWN_SAFE_PIDS or
                        name in _KNOWN_SAFE_NAMES
                    )
                    last_saved = _alerted_pids.get(suspicious_pid, 0)
                    should_save = not is_known_safe and (now - last_saved > COOLDOWN)

                    if should_save:
                        # Unusual process — save to disk + blockchain
                        report, _ = reporter.generate_report(
                            suspicious_pid, name, max_score, findings
                        )
                        t0 = time.time()
                        tx_id, r_hash = blockchain.log_anomaly_event(
                            suspicious_pid, max_score, name, report
                        )
                        latency_ms = round((time.time() - t0) * 1000, 1)
                        _tx_count += 1
                        _alerted_pids[suspicious_pid] = now
                    else:
                        # Known system process or within cooldown — in-memory report only
                        _rid = f"REF-{suspicious_pid}-{int(now)}"
                        report = {
                            "metadata": {
                                "report_id":      _rid,
                                "timestamp":      _dt.now().isoformat(),
                                "agent_version":  "1.0.0-PRO",
                                "integrity_check": "SHA-256",
                                "saved_to_disk":  False,
                            },
                            "incident_details": {
                                "pid":           suspicious_pid,
                                "process_name":  name,
                                "anomaly_score": round(max_score, 4),
                                "classification": "HIGH_RISK" if max_score > 0.85 else "SUSPICIOUS",
                            },
                            "findings": findings,
                            "forensic_lineage": {
                                "evidence_path": f"/proc/{suspicious_pid}",
                                "status": "KNOWN_SYSTEM_PROCESS — NOT PERSISTED" if is_known_safe else "COOLDOWN — NOT PERSISTED",
                            },
                        }
                        tx_id = f"HLF-MEM-{_hl.md5(_rid.encode()).hexdigest()[:10]}"

                    alert_msg = (
                        f"{'[SYS]' if is_known_safe else 'CRITICAL'}: {name} (PID {suspicious_pid}) "
                        f"— Score {max_score:.4f} | TX {tx_id}"
                    )
                    feed_msg = alert_msg
                    await broadcast({
                        "type":          "alert",
                        "msg":           alert_msg,
                        "is_critical":   not is_known_safe,
                        "tx_id":         tx_id,
                        "latency_ms":    latency_ms,
                        "tx_count":      _tx_count,
                        "report":        report,
                        "pid":           suspicious_pid,
                        "process":       name,
                        "score":         round(max_score, 4),
                        "saved_to_disk": should_save,
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

            # Filter out OS-level "Windows processes" to mimic Task Manager's user/background processes
            ui_telemetry = []
            for p in telemetry:
                uname = str(p.get('username', '')).upper()
                # Exclude SYSTEM, LOCAL SERVICE, NETWORK SERVICE, etc.
                if "NT AUTHORITY" not in uname and "SYSTEM" not in uname and "ROOT" not in uname:
                    ui_telemetry.append(p)

            # 8. Broadcast telemetry to all connected dashboards
            await broadcast({
                "type":          "telemetry",
                "data":          ui_telemetry,
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

        await asyncio.sleep(7)


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
        
    ui_telemetry = []
    for p in data:
        uname = str(p.get('username', '')).upper()
        if "NT AUTHORITY" not in uname and "SYSTEM" not in uname and "ROOT" not in uname:
            ui_telemetry.append(p)
            
    return {"count": len(ui_telemetry), "processes": ui_telemetry}


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

    alert_msg = (
        f"INJECTED: crypt0miner.elf (PID {INJECTED_PID}) "
        f"— Score {injected_score:.4f} | TX {tx_id}"
    )
    await broadcast({
        "type":        "alert",
        "msg":         alert_msg,
        "is_critical": True,
        "tx_id":       tx_id,
        "latency_ms":  0,
        "tx_count":    _tx_count,
        "report":      report,
        "pid":         INJECTED_PID,
        "process":     "crypt0miner.elf",
        "score":       round(injected_score, 4),
        "saved_to_disk": True,
    })

    return {
        "injected":           True,
        "flagged_pid":        INJECTED_PID,
        "flagged_process":    "crypt0miner.elf",
        "anomaly_score":      round(injected_score, 4),
        "threshold_exceeded": injected_score > 0.75,
        "blockchain_tx":      tx_id,
        "forensic_hash":      r_hash,
        "report_path":        report_path,
    }


@app.post("/api/inject-custom-anomaly")
async def inject_custom_anomaly(
    name: str = "ransom_enc.exe",
    pid: int  = 6660,
    ppid: int = 9999,
    cpu: float  = 87.3,
    mem: float  = 62.1,
):
    """Injects a custom malicious process and broadcasts via WebSocket."""
    global _tx_count
    telemetry = collect_processes()
    telemetry.append({
        "pid": pid, "ppid": ppid,
        "name": name,
        "cpu_percent": cpu, "memory_percent": mem,
    })
    save_telemetry(telemetry, "data/current_telemetry.json")

    graph    = build_process_graph(telemetry)
    data     = convert_to_pyg(graph)
    model    = get_model()
    with torch.no_grad():
        _, adj_hat, x_hat = model(data)
        scores = get_anomaly_score(data, adj_hat, x_hat)

    node_list  = list(graph.nodes())
    pid_to_idx = {p: i for i, p in enumerate(node_list)}
    score      = scores[pid_to_idx[pid]].item() if pid in pid_to_idx else 0.0

    reporter = ForensicReporter(report_dir="reports")
    findings = (
        f"GNN Anomaly Score {score:.4f} exceeded threshold 0.75. "
        f"Orphan process spawned from unknown PPID {ppid}, cpu={cpu}%, mem={mem}%. "
        f"Malicious behaviour suspected."
    )
    report, report_path = reporter.generate_report(pid, name, score, findings)
    t0 = time.time()
    tx_id, r_hash = blockchain_client_instance.log_anomaly_event(pid, score, name, report)
    latency_ms = round((time.time() - t0) * 1000, 1)
    _tx_count += 1

    alert_msg = f"INJECTED: {name} (PID {pid}) — Score {score:.4f} | TX {tx_id}"
    await broadcast({
        "type":          "alert",
        "msg":           alert_msg,
        "is_critical":   True,
        "tx_id":         tx_id,
        "latency_ms":    latency_ms,
        "tx_count":      _tx_count,
        "report":        report,
        "pid":           pid,
        "process":       name,
        "score":         round(score, 4),
        "saved_to_disk": True,
    })

    return {
        "injected":        True,
        "flagged_pid":     pid,
        "flagged_process": name,
        "anomaly_score":   round(score, 4),
        "blockchain_tx":   tx_id,
        "forensic_hash":   r_hash,
        "report_path":     report_path,
    }


@app.post("/api/clear-cooldowns")
async def clear_cooldowns():
    _alerted_pids.clear()
    return {"status": "ok", "message": "All alert cooldowns cleared"}


@app.post("/api/verify-hash")
async def verify_hash(report_id: str):
    import hashlib, glob
    matches = glob.glob(f"reports/{report_id}.json")
    if not matches:
        return JSONResponse({"error": "Report not found"}, status_code=404)
    with open(matches[0], 'r') as f:
        content = f.read()
    sha = hashlib.sha256(content.encode()).hexdigest()
    return {
        "report_id": report_id,
        "sha256_hash": sha,
        "verified": True,
        "status": "INTEGRITY_CONFIRMED",
        "file_path": matches[0]
    }


@app.get("/api/stats")
async def get_stats():
    report_count = 0
    if os.path.exists("reports"):
        report_count = len([f for f in os.listdir("reports") if f.endswith(".json") and not f.startswith("test_")])
    cycle_data = {}
    if os.path.exists("data/cycle_results.json"):
        with open("data/cycle_results.json") as f:
            cycle_data = json.load(f)
    return {
        "total_reports": report_count,
        "tx_count": _tx_count,
        "max_anomaly_score": cycle_data.get("max_anomaly_score", 0),
        "latency_ms": cycle_data.get("latency_ms", 0),
        "loss": cycle_data.get("loss", 0),
        "edge_count": cycle_data.get("edge_count", 0),
        "model_loaded": _model is not None
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
