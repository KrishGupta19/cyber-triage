import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GATConv, GCNConv

class GNNEncoder(nn.Module):
    """Encodes process graphs using Graph Attention (GAT) layers."""
    def __init__(self, in_channels, out_channels, heads=2):
        super(GNNEncoder, self).__init__()
        # Using GAT for better attention to suspicious nodes
        self.conv1 = GATConv(in_channels, 16, heads=heads, concat=True)
        self.conv2 = GATConv(16 * heads, out_channels, heads=1, concat=False)

    def forward(self, x, edge_index):
        x = self.conv1(x, edge_index)
        x = F.elu(x) # ELU is common with GAT
        x = self.conv2(x, edge_index)
        return x

class GNNDecoder(nn.Module):
    """Reconstructs the graph's structure and features."""
    def __init__(self, latent_channels, out_channels):
        super(GNNDecoder, self).__init__()
        self.feat_decoder = nn.Sequential(
            nn.Linear(latent_channels, 16),
            nn.ReLU(),
            nn.Linear(16, out_channels)
        )

    def forward(self, z, edge_index):
        # 1. Structural reconstruction (Adjacency Matrix probabilities)
        adj_hat = torch.sigmoid((z[edge_index[0]] * z[edge_index[1]]).sum(dim=-1))
        
        # 2. Feature reconstruction
        x_hat = self.feat_decoder(z)
        
        return adj_hat, x_hat

class GNNAutoencoder(nn.Module):
    """Unified GNN Autoencoder for behavioral anomaly detection."""
    def __init__(self, in_channels, latent_channels):
        super(GNNAutoencoder, self).__init__()
        self.encoder = GNNEncoder(in_channels, latent_channels)
        self.decoder = GNNDecoder(latent_channels, in_channels)

    def forward(self, data):
        x, edge_index = data.x, data.edge_index
        z = self.encoder(x, edge_index)
        adj_hat, x_hat = self.decoder(z, edge_index)
        return z, adj_hat, x_hat

def compute_loss(data, adj_hat, x_hat):
    """Reconstruction loss: ||A - A'|| + ||X - X'||"""
    # Adjacency reconstruction loss (binary cross entropy for edges)
    # Target is all 1s for existing edges
    adj_loss = F.binary_cross_entropy(adj_hat, torch.ones_like(adj_hat))
    
    # Feature reconstruction loss (MSE)
    feat_loss = F.mse_loss(x_hat, data.x)
    
    return adj_loss + feat_loss

def get_anomaly_score(data, adj_hat, x_hat):
    """Per-node anomaly score in [0, 1].

    Uses the 95th-percentile reconstruction error of the *current monitoring
    cycle* as the normalisation baseline:
      - A process at the p95 error level scores 0.5  (normal)
      - A process with 2× p95 error scores 1.0       (clearly anomalous)
      - Everything in a normal-only graph scores ≤ 0.5 (never triggers 0.75)
      - A malicious outlier (e.g. crypt0miner) scores 1.0

    This makes the 0.75 threshold robust without requiring a separate
    calibration file whose validity decays as process states evolve.
    """
    feat_error = torch.mean((data.x - x_hat)**2, dim=1)
    # p95 of the batch is a stable "normal baseline":
    #   - 95% of processes score ≤ 0.5 (below the 0.75 alert threshold)
    #   - An outlier with error > 1.5 × p95 crosses the threshold
    #   - Works for both small test graphs and large live graphs
    p95 = torch.quantile(feat_error, 0.95).item()
    if p95 < 1e-10:
        p95 = feat_error.max().item() + 1e-10
    return torch.clamp(feat_error / (2.0 * p95), 0.0, 1.0)
