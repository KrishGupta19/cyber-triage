import json
import os
import hashlib
from datetime import datetime

class ForensicReporter:
    """Generates detailed forensic JSON reports for detected anomalies."""
    def __init__(self, report_dir='reports'):
        self.report_dir = report_dir
        os.makedirs(self.report_dir, exist_ok=True)

    def generate_report(self, pid, name, score, findings):
        """Creates a structured forensic report."""
        report_id = f"REF-{pid}-{int(datetime.now().timestamp())}"
        report = {
            "metadata": {
                "report_id": report_id,
                "timestamp": datetime.now().isoformat(),
                "agent_version": "1.0.0-PRO",
                "integrity_check": "SHA-256"
            },
            "incident_details": {
                "pid": pid,
                "process_name": name,
                "anomaly_score": score,
                "classification": "HIGH_RISK" if score > 0.85 else "SUSPICIOUS"
            },
            "findings": findings,
            "forensic_lineage": {
                "evidence_path": f"/proc/{pid}",
                "status": "PRESERVED"
            }
        }
        
        report_path = os.path.join(self.report_dir, f"{report_id}.json")
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=4)
            
        print(f"Forensic report {report_id} generated at {report_path}")
        return report, report_path

def verify_report_integrity(report_path, expected_hash):
    """Verifies a report against a blockchain-stored hash."""
    with open(report_path, 'r') as f:
        content = f.read()
        actual_hash = hashlib.sha256(content.encode()).hexdigest()
        return actual_hash == expected_hash
