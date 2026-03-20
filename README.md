# Decentralised & Behavioural Analytical Cyber Triage Tool

A real-time cyber triage tool using Graph Neural Networks (GNN) for behavioral anomaly detection and Hyperledger Fabric for immutable forensic logging.

## Project Structure
- `src/`: Core logic (Collector, Graph Builder, GNN Model, Blockchain Client).
- `data/`: Local storage for process telemetry and baseline data.
- `models/`: Trained GNN model checkpoints.
- `reports/`: Forensic JSON reports.

## Setup
1. Install dependencies: `pip install -r requirements.txt`
2. Configure Hyperledger Fabric network (see `docs/blockchain_setup.md`).
3. Run the data collector: `python src/collector.py`
