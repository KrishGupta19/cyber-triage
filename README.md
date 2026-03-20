# CyberTriage OS — v2.0

A real-time cyber triage dashboard powered by a GNN Autoencoder for process-level anomaly detection, with simulated Hyperledger Fabric blockchain logging.

---

## What it does

- Collects live system process telemetry every 5 seconds
- Builds a process DAG (parent → child) and runs it through a GNN Autoencoder
- Scores each process for behavioural anomaly (0.0 = normal, 1.0 = highly anomalous)
- Displays live charts, process scores, graph visualisation, and reconstruction loss
- Commits anomaly events to a simulated Hyperledger Fabric blockchain
- Generates forensic reports for flagged processes

---

## Running the project

### Option A — Docker (recommended, no Python needed)

**Requirements:** [Docker Desktop](https://www.docker.com/products/docker-desktop/) only

```bash
# 1. Clone the repo
git clone <your-repo-url>
cd cyber_triage

# 2. Build the image  (~5–10 min first time, PyTorch is ~200 MB)
docker build -t cybertriage .

# 3a. Linux/Mac — share host PID namespace to monitor real host processes
docker run -p 8000:8000 --pid=host cybertriage

# 3b. Windows — works but monitors container processes only (see note below)
docker run -p 8000:8000 cybertriage

# 4. Open in browser
http://localhost:8000
```

---

### Option B — Python directly (best on Windows)

**Requirements:** Python 3.10 or 3.11

```bash
# 1. Clone the repo
git clone <your-repo-url>
cd cyber_triage

# 2. Install PyTorch first (must come before torch-geometric)
pip install torch==2.10.0 --index-url https://download.pytorch.org/whl/cpu

# 3. Install PyTorch Geometric
pip install torch-geometric==2.7.0

# 4. Install remaining dependencies
pip install psutil fastapi "uvicorn[standard]" networkx python-multipart requests

# 5. Start the dashboard
python src/dashboard.py       # Linux / Mac
py src/dashboard.py           # Windows

# 6. Open in browser
http://localhost:8000
```

---

## Testing with a simulated anomaly

Once the dashboard is running, inject a fake `crypt0miner.elf` process to trigger the full detection pipeline:

```bash
curl -X POST http://localhost:8000/api/inject-test-anomaly
```

This will:
1. Inject a high-CPU orphan process into the telemetry
2. Run it through the GNN — anomaly score spikes to ~1.0
3. Generate a forensic report under `reports/`
4. Commit the event to the simulated blockchain
5. Show a red alert block in the dashboard's blockchain log panel

---

## REST API

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Server health check |
| GET | `/api/processes` | Latest 25 processes with anomaly scores |
| GET | `/api/anomalies` | All forensic reports generated so far |
| POST | `/api/inject-test-anomaly` | Inject a fake malicious process |

---

## Docker note — Windows and Mac

Docker on Windows and Mac runs inside a Linux VM, so `--pid=host` shares that VM's process list rather than your host OS processes. The dashboard works fully — it just monitors the VM's processes instead of your Windows/Mac ones. **On Linux, `--pid=host` gives complete visibility into real host processes.**

---

## Project structure

```
cyber_triage/
├── src/
│   ├── dashboard.py         # FastAPI server + WebSocket + triage loop
│   ├── collector.py         # psutil process collection
│   ├── graph_builder.py     # NetworkX DAG + PyG conversion
│   ├── model.py             # GNN Autoencoder (GAT encoder + MLP decoder)
│   ├── train_model.py       # Offline model training
│   ├── blockchain_client.py # Simulated Hyperledger Fabric client
│   └── forensic_reporter.py # JSON forensic report generation
├── static/
│   └── index.html           # Dashboard UI (Chart.js + Canvas)
├── models/
│   └── gnn_baseline.pt      # Trained GNN weights
├── data/                    # Telemetry and baseline datasets
├── reports/                 # Generated forensic reports (runtime)
├── Dockerfile
└── requirements.txt
```
