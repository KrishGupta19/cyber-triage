import json
import networkx as nx
import torch
from torch_geometric.data import Data
import os

def load_telemetry(file_path='data/gnn_baseline_data.json'):
    """Loads process telemetry from JSON."""
    if not os.path.exists(file_path):
        print(f"Error: {file_path} not found.")
        return []
    with open(file_path, 'r') as f:
        return json.load(f)

def build_process_graph(telemetry):
    """Constructs a Directed Acyclic Graph (DAG) from process telemetry."""
    G = nx.DiGraph()

    # Build lookup for process metadata (for feature encoding)
    proc_lookup = {p['pid']: p for p in telemetry}

    # Track all PIDs to identify orphans
    pids = {p['pid'] for p in telemetry}

    # Ensure synthetic root exists
    if 0 not in pids:
        G.add_node(0, name='[root]', cpu_percent=0.0, memory_percent=0.0)

    for proc in telemetry:
        pid = proc['pid']
        ppid = proc['ppid']
        name = proc['name']
        cpu = proc.get('cpu_percent', 0.0) or 0.0
        mem = proc.get('memory_percent', 0.0) or 0.0

        # Add node with behavioural features
        G.add_node(pid, name=name, cpu_percent=cpu, memory_percent=mem)

        # Add edge from PPID to PID if PPID exists in the trace
        if ppid in pids:
            G.add_edge(ppid, pid)
        else:
            # Connect orphan PIDs to a synthetic root (PID 0)
            G.add_edge(0, pid)

    return G

def convert_to_pyg(G):
    """Converts a NetworkX graph to a PyTorch Geometric Data object.

    Uses FIXED normalisation constants so features are always on the same
    scale whether during training or live inference.  This is essential for
    the GNN Autoencoder's anomaly scores to be meaningful.
    """
    # Create a mapping from PID to contiguous indices [0, N-1]
    node_list = list(G.nodes())
    mapping = {pid: i for i, pid in enumerate(node_list)}

    edges = []
    for u, v in G.edges():
        edges.append([mapping[u], mapping[v]])

    edge_index = torch.tensor(edges, dtype=torch.long).t().contiguous()

    num_nodes = G.number_of_nodes()
    x = torch.zeros((num_nodes, 16))

    # Fixed normalisation constants — same for training AND inference
    CPU_MAX = 100.0    # cpu_percent is always 0-100 per process
    MEM_MAX = 100.0    # memory_percent is always 0-100
    PID_MAX = 65536.0  # practical Linux/Windows PID upper bound

    for pid, i in mapping.items():
        attrs = G.nodes[pid]
        cpu = min((attrs.get('cpu_percent', 0.0) or 0.0), CPU_MAX) / CPU_MAX
        mem = min((attrs.get('memory_percent', 0.0) or 0.0), MEM_MAX) / MEM_MAX
        pid_norm = min(pid, PID_MAX) / PID_MAX if isinstance(pid, int) else 0.0
        x[i, 0] = cpu
        x[i, 1] = mem
        x[i, 2] = pid_norm
        x[i, 3] = 1.0  # constant bias

    return Data(x=x, edge_index=edge_index)

if __name__ == "__main__":
    print("Building process graph...")
    data = load_telemetry()
    if data:
        graph = build_process_graph(data)
        pyg_data = convert_to_pyg(graph)
        print(f"Graph built with {graph.number_of_nodes()} nodes and {graph.number_of_edges()} edges.")
        print(f"PyTorch Geometric Data: {pyg_data}")
        
        # Save graph object if needed
        # torch.save(pyg_data, 'data/process_graph.pt')
