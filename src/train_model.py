import torch
import torch.optim as optim
from model import GNNAutoencoder, compute_loss
from graph_builder import load_telemetry, build_process_graph, convert_to_pyg
import os

def train_gnn():
    """Trains the GNN Autoencoder on the baseline telemetry data."""
    print("Loading baseline telemetry...")
    telemetry = load_telemetry('data/gnn_baseline_data.json')
    if not telemetry:
        print("Error: No baseline data found.")
        return

    # Build graph and convert to PyG format
    graph = build_process_graph(telemetry)
    data = convert_to_pyg(graph)
    
    # Initialize model, optimizer
    model = GNNAutoencoder(in_channels=16, latent_channels=8)
    optimizer = optim.Adam(model.parameters(), lr=0.01)
    
    model.train()
    print("Starting GNN training loop...")
    
    for epoch in range(1, 101):
        optimizer.zero_grad()
        # Forward pass
        z, adj_hat, x_hat = model(data)
        
        # Loss calculation
        loss = compute_loss(data, adj_hat, x_hat)
        
        # Backprop
        loss.backward()
        optimizer.step()
        
        if epoch % 10 == 0:
            print(f"Epoch {epoch:03d} | Loss: {loss.item():.4f}")
            
    # Save model checkpoint
    os.makedirs('models', exist_ok=True)
    torch.save(model.state_dict(), 'models/gnn_baseline.pt')
    print("Training complete. Model saved to models/gnn_baseline.pt")

    # Compute and save baseline reconstruction error using the same combined
    # metric (70% feature + 30% structural) that get_anomaly_score uses at
    # runtime, so the saved p95 is on the same scale as live scores.
    model.eval()
    with torch.no_grad():
        z_b, adj_hat_b, x_hat_b = model(data)
        feat_errors = torch.mean((data.x - x_hat_b) ** 2, dim=1)

        if data.edge_index.size(1) > 0:
            src = data.edge_index[0]
            edge_struct_err = (1.0 - adj_hat_b) ** 2
            node_struct_err = torch.zeros(z_b.size(0))
            node_count      = torch.zeros(z_b.size(0))
            node_struct_err.scatter_add_(0, src, edge_struct_err)
            node_count.scatter_add_(0, src, torch.ones_like(edge_struct_err))
            node_struct_err = node_struct_err / node_count.clamp(min=1.0)
            combined = 0.7 * feat_errors + 0.3 * node_struct_err
        else:
            combined = feat_errors

        p95 = torch.quantile(combined, 0.95).item()
        p99 = torch.quantile(combined, 0.99).item()

    torch.save({'p95_error': p95, 'p99_error': p99}, 'models/anomaly_threshold.pt')
    print(f"Baseline combined-error p95={p95:.6f}  p99={p99:.6f} saved to models/anomaly_threshold.pt")

if __name__ == "__main__":
    train_gnn()
