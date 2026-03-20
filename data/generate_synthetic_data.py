import json
import random
import os

def generate_normal_baseline(num_samples=500):
    """Generates synthetic 'normal' process telemetry."""
    baseline = []
    # Standard system processes
    common_procs = [
        {'pid': 1, 'ppid': 0, 'name': 'systemd'},
        {'pid': 102, 'ppid': 1, 'name': 'dbus-daemon'},
        {'pid': 105, 'ppid': 1, 'name': 'networkd'},
        {'pid': 200, 'ppid': 1, 'name': 'sshd'},
        {'pid': 500, 'ppid': 200, 'name': 'bash'},
        {'pid': 800, 'ppid': 1, 'name': 'nginx'},
        {'pid': 801, 'ppid': 800, 'name': 'nginx-worker'},
    ]
    
    for i in range(num_samples):
        # Add some random variations in CPU/Memory
        for p in common_procs:
            proc_copy = p.copy()
            proc_copy['cpu_percent'] = random.uniform(0.1, 5.0)
            proc_copy['memory_percent'] = random.uniform(0.5, 2.0)
            baseline.append(proc_copy)
            
    return baseline

def generate_attack_samples():
    """Generates synthetic 'attack' process telemetry (e.g. reverse shells)."""
    attacks = [
        # Reverse Shell: sshd -> bash -> nc (netcat)
        {'pid': 9001, 'ppid': 1, 'name': 'sshd'},
        {'pid': 9002, 'ppid': 9001, 'name': 'bash'},
        {'pid': 9003, 'ppid': 9002, 'name': 'nc'}, # Suspicious leaf
        
        # Crypto Miner: rogue child of a web server
        {'pid': 800, 'ppid': 1, 'name': 'nginx'},
        {'pid': 9999, 'ppid': 800, 'name': 'crypt0miner.elf', 'cpu_percent': 98.5},
        
        # Privilege Escalation: SUID exploit
        {'pid': 500, 'ppid': 1, 'name': 'bash'},
        {'pid': 9921, 'ppid': 500, 'name': 'pkexec', 'findings': 'Possible SUID exploit'}
    ]
    return attacks

if __name__ == "__main__":
    os.makedirs('data', exist_ok=True)
    
    print("Generating synthetic datasets...")
    normal_data = generate_normal_baseline()
    attack_data = generate_attack_samples()
    
    with open('data/gnn_baseline_data.json', 'w') as f:
        json.dump(normal_data, f, indent=4)
        
    with open('data/attack_telemetry.json', 'w') as f:
        json.dump(attack_data, f, indent=4)
        
    print(f"Generated {len(normal_data)} normal samples and {len(attack_data)} attack samples.")
