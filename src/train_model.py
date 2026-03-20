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

    # Compute and save baseline reconstruction error statistics for score calibration
    model.eval()
    with torch.no_grad():
        _, _, x_hat_baseline = model(data)
        feat_errors = torch.mean((data.x - x_hat_baseline)**2, dim=1)
        p95 = torch.quantile(feat_errors, 0.95).item()
        p99 = torch.quantile(feat_errors, 0.99).item()
    torch.save({'p95_error': p95, 'p99_error': p99}, 'models/anomaly_threshold.pt')
    print(f"Baseline error p95={p95:.6f}  p99={p99:.6f} saved to models/anomaly_threshold.pt")

if __name__ == "__main__":
    train_gnn()
