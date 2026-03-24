# CyberTriage — v2.0

A real-time cybersecurity triage dashboard powered by a GNN Autoencoder for process-level anomaly detection, with simulated Hyperledger Fabric blockchain logging and an AI cybersecurity assistant.

---

## What it does

- Collects live system process telemetry every 7 seconds via `psutil`
- Builds a process parent→child DAG and runs it through a GNN Autoencoder (GAT encoder + MLP decoder)
- Scores each process for behavioural anomaly (0.0 = normal, 1.0 = highly anomalous)
- Alerts on processes scoring above 0.75 threshold
- Commits anomaly events to a simulated Hyperledger Fabric blockchain with SHA-256 integrity
- Generates JSON forensic reports for flagged processes
- Auto-retrains the model every 2 minutes on clean telemetry (continuous learning)
- Live WebSocket dashboard with auto-reconnect

---

## Quick start — Python (recommended on Windows)

**Requires Python 3.10 or 3.11** (not 3.12+, due to torch-geometric compatibility)

```bash
# 1. Clone the repo
git clone <your-repo-url>
cd cyber_triage

# 2. Install PyTorch first (must come before torch-geometric)
pip install torch==2.10.0 --index-url https://download.pytorch.org/whl/cpu

# 3. Install PyTorch Geometric
pip install torch-geometric==2.7.0

# 4. Install remaining dependencies
pip install psutil fastapi "uvicorn[standard]" networkx python-multipart requests anthropic

# 5. (Optional) Set your Anthropic API key to enable the AI assistant
#    Without this the dashboard works fully — only the chat tab is disabled
set ANTHROPIC_API_KEY=sk-ant-...        # Windows
export ANTHROPIC_API_KEY=sk-ant-...     # Linux / Mac

# 6. Start the dashboard
py src/dashboard.py          # Windows
python src/dashboard.py      # Linux / Mac

# 7. Open in browser
http://localhost:8000
```

---

## Quick start — Docker

**Requires:** [Docker Desktop](https://www.docker.com/products/docker-desktop/)

```bash
# 1. Clone and build (~5-10 min first time, PyTorch is large)
git clone <your-repo-url>
cd cyber_triage
docker build -t cybertriage .

# 2a. Linux — share host PID namespace to monitor real host processes
docker run -p 8000:8000 --pid=host -e ANTHROPIC_API_KEY=sk-ant-... cybertriage

# 2b. Windows / Mac — works but monitors container processes only
docker run -p 8000:8000 -e ANTHROPIC_API_KEY=sk-ant-... cybertriage

# 3. Open browser
http://localhost:8000
```

> **Docker note:** On Windows and Mac, Docker runs in a Linux VM so `--pid=host` shows that VM's processes, not your host OS. The dashboard works fully — it just monitors the VM. On Linux, `--pid=host` gives complete visibility into real host processes.

---

## Testing with a simulated attack

Once the dashboard is running, click **⚡ Inject Test Attack** in the header, or run:

```bash
curl -X POST http://localhost:8000/api/inject-test-anomaly
```

This injects a fake `crypt0miner.elf` process and runs the full detection pipeline:
1. Process is added to live telemetry
2. GNN scores it — anomaly score spikes
3. Forensic report generated under `reports/`
4. Event committed to simulated blockchain
5. Red alert block appears in the dashboard

---

## REST API

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Server health check |
| GET | `/api/processes` | Live processes with anomaly scores |
| GET | `/api/anomalies` | All forensic reports |
| GET | `/api/stats` | System overview stats |
| POST | `/api/inject-test-anomaly` | Inject fake `crypt0miner.elf` |
| POST | `/api/inject-custom-anomaly` | Inject custom process (name/pid/cpu/mem params) |
| POST | `/api/clear-cooldowns` | Reset 5-min alert cooldowns |
| POST | `/api/verify-hash?report_id=REF-...` | Verify SHA-256 integrity of a report |
| POST | `/api/chat` | AI cybersecurity assistant (requires ANTHROPIC_API_KEY) |

---

## Running tests

```bash
# Run with server already started in another terminal
py -m pytest tests/test_all.py -v
```

---

## Project structure

```
cyber_triage/
├── src/
│   ├── dashboard.py         # FastAPI server + WebSocket + triage loop
│   ├── collector.py         # psutil live process collection
│   ├── graph_builder.py     # NetworkX DAG + PyG conversion
│   ├── model.py             # GNN Autoencoder (GAT encoder + MLP decoder)
│   ├── train_model.py       # Offline model training script
│   ├── blockchain_client.py # Simulated Hyperledger Fabric client
│   └── forensic_reporter.py # JSON forensic report generation
├── static/
│   └── index.html           # Live dashboard UI
├── models/
│   ├── gnn_baseline.pt      # Trained GNN weights (included in repo)
│   └── anomaly_threshold.pt # Baseline error thresholds
├── data/
│   └── gnn_baseline_data.json  # Training telemetry (included in repo)
├── reports/                 # Generated forensic reports (runtime)
├── tests/
│   └── test_all.py          # Test suite
├── Dockerfile
└── requirements.txt
```
