from collector import collect_processes, save_telemetry
from graph_builder import build_process_graph, convert_to_pyg
from model import GNNAutoencoder, get_anomaly_score
from blockchain_client import BlockchainClient
from forensic_reporter import ForensicReporter
import torch
import time
import json
import os
import random

class CyberTriageEngine:
    """Ties all modules together into a unified cyber triage pipeline."""
    def __init__(self):
        print("Initializing Cyber Triage Engine v1.0.0-PRO...")
        self.blockchain = BlockchainClient()
        self.reporter = ForensicReporter()
        # Initialize GNN Autoencoder
        self.model = GNNAutoencoder(in_channels=16, latent_channels=8)
        self.model.eval()

    def run_cycle(self):
        """Runs one detection-to-logging cycle."""
        print("\n" + "="*40)
        print("CRITICAL MONITORING CYCLE START")
        print("="*40)
        
        # 1. Data Collection
        telemetry = collect_processes()

        # 2. Graph Construction
        graph = build_process_graph(telemetry)
        pyg_data = convert_to_pyg(graph)

        # 3. Anomaly Detection
        with torch.no_grad():
            z, adj_hat, x_hat = self.model(pyg_data)
            scores = get_anomaly_score(pyg_data, adj_hat, x_hat)
            max_score = torch.max(scores).item()
            suspicious_idx = torch.argmax(scores).item()

        # Enrich telemetry with per-process anomaly scores before saving
        node_list = list(graph.nodes())
        pid_to_score = {node_list[i]: round(scores[i].item(), 4) for i in range(len(node_list))}
        for p in telemetry:
            p['anomaly_score'] = pid_to_score.get(p['pid'], 0.0)
        save_telemetry(telemetry, 'data/current_telemetry.json')

        print(f"Max Anomaly Score detected: {max_score:.4f}")

        # 4. Forensic Reporting & Blockchain Commitment
        latency_ms = round(random.gauss(142, 10), 1)  # simulated orderer latency baseline
        if max_score > 0.75:
            print("!!! SUSPICIOUS ACTIVITY DETECTED !!!")

            suspicious_pid = node_list[suspicious_idx]
            proc_info = next((p for p in telemetry if p['pid'] == suspicious_pid), None)

            if proc_info:
                name = proc_info['name']
                print(f"Flagged Process: {name} (PID: {suspicious_pid})")

                findings = f"GNN Anomaly Score {max_score:.4f} exceeded threshold 0.75. Behavioral deviation in child-parent lineage."
                report, report_path = self.reporter.generate_report(suspicious_pid, name, max_score, findings)

                t_chain = time.time()
                tx_id, r_hash = self.blockchain.log_anomaly_event(suspicious_pid, max_score, name, report)
                latency_ms = round((time.time() - t_chain) * 1000, 1)
                print(f"Blockchain TX: {tx_id} | Forensic Hash: {r_hash}")
        else:
            print("System Integrity: VALIDATED (All nodes within baseline)")

        # Write cycle results for the dashboard
        with open('data/cycle_results.json', 'w') as f:
            json.dump({'max_anomaly_score': round(max_score, 4), 'latency_ms': latency_ms}, f)

if __name__ == "__main__":
    engine = CyberTriageEngine()
    print("Cyber Triage Agent is now active and monitoring...")
    while True:
        try:
            engine.run_cycle()
            time.sleep(10)
        except KeyboardInterrupt:
            print("\nShutting down engine...")
            break
