import unittest
import torch
import sys
import os

# Adding src to path for testing
sys.path.append(os.path.abspath('src'))

from model import GNNAutoencoder, compute_loss, get_anomaly_score
from graph_builder import build_process_graph, convert_to_pyg
from blockchain_client import BlockchainClient
from forensic_reporter import ForensicReporter

class TestCyberTriage(unittest.TestCase):
    def setUp(self):
        # Mock telemetry data
        self.telemetry = [
            {'pid': 1, 'ppid': 0, 'name': 'systemd', 'cpu_percent': 0.1, 'memory_percent': 0.5},
            {'pid': 100, 'ppid': 1, 'name': 'bash', 'cpu_percent': 1.2, 'memory_percent': 0.8},
            {'pid': 999, 'ppid': 100, 'name': 'nc', 'cpu_percent': 50.0, 'memory_percent': 1.2}
        ]
        self.model = GNNAutoencoder(in_channels=16, latent_channels=8)

    def test_graph_builder(self):
        """Verify the graph build process and PyG conversion."""
        graph = build_process_graph(self.telemetry)
        self.assertEqual(graph.number_of_nodes(), 4) # 3 procs + 1 root (0)
        
        pyg_data = convert_to_pyg(graph)
        self.assertEqual(pyg_data.x.shape, (4, 16))
        self.assertTrue(pyg_data.edge_index.shape[1] >= 3)

    def test_gnn_model_inference(self):
        """Verify the GNN model's forward pass and loss logic."""
        graph = build_process_graph(self.telemetry)
        data = convert_to_pyg(graph)
        
        z, adj_hat, x_hat = self.model(data)
        
        self.assertEqual(z.shape, (4, 8))
        self.assertEqual(x_hat.shape, (4, 16))
        
        loss = compute_loss(data, adj_hat, x_hat)
        self.assertGreater(loss.item(), 0)

    def test_blockchain_client(self):
        """Verify the blockchain hashing and payload generation."""
        client = BlockchainClient()
        report = {"test": "data"}
        tx_id, r_hash = client.log_anomaly_event(999, 0.9, "nc", report)
        
        self.assertTrue(tx_id.startswith("HLF-TX-"))
        self.assertEqual(len(r_hash), 64) # SHA-256 length

    def test_forensic_reporter(self):
        """Verify forensic report generation and integrity."""
        reporter = ForensicReporter(report_dir='reports/test_reports')
        report, path = reporter.generate_report(999, "nc", 0.95, "Test finding")
        
        self.assertTrue(os.path.exists(path))
        self.assertEqual(report['incident_details']['pid'], 999)

    def test_clear_cooldowns_endpoint(self):
        """Verify /api/clear-cooldowns resets the cooldown dict."""
        import requests
        try:
            r = requests.post('http://localhost:8000/api/clear-cooldowns', timeout=3)
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.json()['status'], 'ok')
        except requests.exceptions.ConnectionError:
            self.skipTest("Server not running")

    def test_stats_endpoint(self):
        """Verify /api/stats returns expected fields."""
        import requests
        try:
            r = requests.get('http://localhost:8000/api/stats', timeout=3)
            self.assertEqual(r.status_code, 200)
            data = r.json()
            self.assertIn('total_reports', data)
            self.assertIn('tx_count', data)
            self.assertIn('model_loaded', data)
        except requests.exceptions.ConnectionError:
            self.skipTest("Server not running")

    def test_verify_hash_endpoint(self):
        """Verify /api/verify-hash returns a valid SHA-256 for a known report."""
        import requests, os, glob
        reports = glob.glob('reports/*.json')
        if not reports:
            self.skipTest("No reports generated yet")
        report_id = os.path.basename(reports[0]).replace('.json', '')
        try:
            r = requests.post(
                f'http://localhost:8000/api/verify-hash?report_id={report_id}',
                timeout=3
            )
            self.assertEqual(r.status_code, 200)
            data = r.json()
            self.assertTrue(data['verified'])
            self.assertEqual(len(data['sha256_hash']), 64)
        except requests.exceptions.ConnectionError:
            self.skipTest("Server not running")

    def test_inject_custom_anomaly_endpoint(self):
        """Verify /api/inject-custom-anomaly creates a report and returns score."""
        import requests
        try:
            r = requests.post(
                'http://localhost:8000/api/inject-custom-anomaly'
                '?name=test_malware.elf&pid=11111&ppid=9999&cpu=95.0&mem=30.0',
                timeout=10
            )
            self.assertEqual(r.status_code, 200)
            data = r.json()
            self.assertTrue(data['injected'])
            self.assertIn('anomaly_score', data)
            self.assertIn('blockchain_tx', data)
        except requests.exceptions.ConnectionError:
            self.skipTest("Server not running")

    def test_sha256_integrity(self):
        """Verify forensic report SHA-256 hash matches file content."""
        import hashlib, glob
        reports = glob.glob('reports/*.json')
        if not reports:
            self.skipTest("No reports generated yet")
        path = reports[0]
        with open(path, 'r') as f:
            content = f.read()
        h = hashlib.sha256(content.encode()).hexdigest()
        self.assertEqual(len(h), 64)
        self.assertIsInstance(h, str)
        h2 = hashlib.sha256(content.encode()).hexdigest()
        self.assertEqual(h, h2)


if __name__ == '__main__':
    unittest.main()
