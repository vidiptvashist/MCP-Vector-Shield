import os
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"

import json
import numpy as np
from mcp_vector_shield.mcp_registry import MCPSemanticRegistry

def main():
    registry = MCPSemanticRegistry(distance_threshold=0.3, device="cpu")
    
    with open("safe_baselines.json", "r") as f:
        safe_tools = json.load(f)
    for tool in safe_tools:
        registry.register_baseline(tool)
        
    with open("poisoned_tests.json", "r") as f:
        poisoned_tools = json.load(f)
        
    print("Analyzing distances for Safe Minor Updates...")
    safe_update_distances = []
    for tool in safe_tools:
        modified_tool = {
            "name": tool["name"],
            "description": tool["description"] + " Updated with standard performance optimizations.",
            "inputSchema": tool["inputSchema"]
        }
        # Measure actual distance
        vec = registry.model.encode(registry._serialize_tool(modified_tool))
        # Find baseline
        baseline_idx = registry.tool_to_id[tool["name"]]
        baseline_vec = np.zeros((1, registry.index.d), dtype="float32")
        registry.index.reconstruct(baseline_idx, baseline_vec[0])
        dist = np.sum((vec - baseline_vec) ** 2)
        safe_update_distances.append(dist)
        
    print("Analyzing distances for Poisoned Shadowing Attacks...")
    poisoned_distances = []
    for tool in poisoned_tools:
        vec = registry.model.encode(registry._serialize_tool(tool))
        baseline_idx = registry.tool_to_id[tool["name"]]
        baseline_vec = np.zeros((1, registry.index.d), dtype="float32")
        registry.index.reconstruct(baseline_idx, baseline_vec[0])
        dist = np.sum((vec - baseline_vec) ** 2)
        poisoned_distances.append(dist)
        
    print("\nDistance Statistics:")
    print(f"Safe Updates: min={np.min(safe_update_distances):.4f}, max={np.max(safe_update_distances):.4f}, mean={np.mean(safe_update_distances):.4f}, p95={np.percentile(safe_update_distances, 95):.4f}")
    print(f"Poisoned Attacks: min={np.min(poisoned_distances):.4f}, max={np.max(poisoned_distances):.4f}, mean={np.mean(poisoned_distances):.4f}, p5={np.percentile(poisoned_distances, 5):.4f}")
    
    # Try to find a threshold with 0 false positives
    max_safe_update = np.max(safe_update_distances)
    print(f"\nRecommended threshold to guarantee 0 False Positives: {max_safe_update:.4f}")
    
    # Calculate detection rate at different thresholds
    for t in [0.05, 0.10, 0.15, 0.20, 0.25, 0.30]:
        fp = sum(1 for d in safe_update_distances if d > t)
        tp = sum(1 for d in poisoned_distances if d > t)
        print(f"Threshold={t:.2f}: False Positive Rate={fp/len(safe_tools)*100:.1f}%, True Positive Rate={tp/len(poisoned_tools)*100:.1f}%")

if __name__ == "__main__":
    main()
