import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GATConv, GCNConv

class GNNEncoder(nn.Module):
    """Encodes process graphs using Graph Attention (GAT) layers."""
    def __init__(self, in_channels, out_channels, heads=2, dropout=0.3):
        super(GNNEncoder, self).__init__()
        self.conv1 = GATConv(in_channels, 16, heads=heads, concat=True)
        self.conv2 = GATConv(16 * heads, out_channels, heads=1, concat=False)
        self.dropout = nn.Dropout(p=dropout)

    def forward(self, x, edge_index):
        x = self.conv1(x, edge_index)
        x = F.elu(x)
        x = self.dropout(x)  # regularise latent space during fine-tuning
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

def compute_loss(data, adj_hat, x_hat, z=None):
    """Reconstruction loss: ||A - A'|| + ||X - X'|| + optional negative-edge loss.

    When z (the latent embeddings) is supplied, negative edge sampling is
    activated.  The model is penalised for assigning high edge-probability to
    randomly sampled non-edge pairs, fixing the one-sided positive-only bias
    of the original adjacency loss.
    """
    # Positive-edge adjacency loss — existing edges should reconstruct to 1
    adj_loss = F.binary_cross_entropy(adj_hat, torch.ones_like(adj_hat))

    # Feature reconstruction loss
    feat_loss = F.mse_loss(x_hat, data.x)

    # Negative-edge loss — sample random pairs that are likely non-edges and
    # penalise high predicted connectivity for them.
    neg_loss = torch.tensor(0.0, device=adj_hat.device)
    if z is not None and z.size(0) > 1 and adj_hat.size(0) > 0:
        num_nodes = z.size(0)
        num_neg = adj_hat.size(0)
        neg_src = torch.randint(0, num_nodes, (num_neg,), device=z.device)
        neg_dst = torch.randint(0, num_nodes, (num_neg,), device=z.device)
        neg_adj = torch.sigmoid((z[neg_src] * z[neg_dst]).sum(dim=-1))
        neg_loss = F.binary_cross_entropy(neg_adj, torch.zeros_like(neg_adj))

    return adj_loss + feat_loss + 0.5 * neg_loss

def get_anomaly_score(data, adj_hat, x_hat, z=None):
    """Per-node anomaly score in [0, 1].

    Combines feature reconstruction error (70%) with structural reconstruction
    error (30%) when edge data is available.  Normalised against the p95 of
    the current batch so scores are always on a consistent 0–1 scale.
    """
    feat_error = torch.mean((data.x - x_hat) ** 2, dim=1)

    if z is not None and data.edge_index.size(1) > 0:
        src = data.edge_index[0]
        edge_struct_err = (1.0 - adj_hat) ** 2
        node_struct_err = torch.zeros(z.size(0), device=z.device)
        node_count      = torch.zeros(z.size(0), device=z.device)
        node_struct_err.scatter_add_(0, src, edge_struct_err)
        node_count.scatter_add_(0, src, torch.ones_like(edge_struct_err))
        node_struct_err = node_struct_err / node_count.clamp(min=1.0)
        combined = 0.7 * feat_error + 0.3 * node_struct_err
    else:
        combined = feat_error

    p95 = torch.quantile(combined, 0.95).item()
    if p95 < 1e-10:
        p95 = combined.max().item() + 1e-10
    return torch.clamp(combined / (2.0 * p95), 0.0, 1.0)
