
import sys
import math
import numpy as np
from collections import Counter
from scipy.stats import entropy

def get_distribution(data, bins=10):
    """Convert raw data to a probability distribution."""
    # Simplified for discrete LSB (0/1) or small-range distribution
    counts = Counter(data)
    total = len(data)
    # Ensure all bins (0, 1) exist
    probs = [counts.get(i, 0) / total for i in range(bins)]
    return np.array(probs)

def calculate_kl(dist_a, dist_b):
    """KL divergence: sum(P(i) * log(P(i)/Q(i)))"""
    # Adding small epsilon to avoid log(0)
    eps = 1e-10
    dist_a = dist_a + eps
    dist_b = dist_b + eps
    return entropy(dist_a, dist_b)

# --- Mock Baseline Data ---
# 1. Natural Bios (LLM-generated sample)
natural_bios = [
    "Software Engineer focusing on distributed systems.",
    "Passionate about building scalable web platforms.",
    "Designing robust backend architectures in Go.",
    "Fullstack developer, love working with React.",
    "Data scientist exploring machine learning models."
]
# 2. Natural Scores (Gauß-verteilt 0.78, 0.12)
natural_scores = np.random.normal(0.78, 0.12, 1000)

def get_bio_dist(bios):
    # Simplified: Distribution of first characters
    first_chars = [ord(b[0]) % 2 for b in bios if b]
    return get_distribution(first_chars, bins=2)

def get_score_dist(scores):
    # Distribution of LSB (0 or 1)
    lsbs = [int(round(s * 1000000)) % 2 for s in scores]
    return get_distribution(lsbs, bins=2)

# --- Analyze Baseline vs GhostAudit ---
# (Wird in nächsten Schritten mit audit.db gefüllt)
print("KL-Baseline für Stego-Resistenz bereit.")
