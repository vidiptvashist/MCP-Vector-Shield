import os
# Suppress openmp conflicts segfault
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"

import json
from mcp_vector_shield.mcp_registry import MCPSemanticRegistry

def main():
    print("=" * 70)
    print("      MCP Vector Semantic Registry Shadowing Detection Benchmark      ")
    print("=" * 70)
    
    # We use an L2 distance threshold of 0.05, calibrated for normalized embeddings
    print("[1/4] Initializing MCPSemanticRegistry...")
    registry = MCPSemanticRegistry(distance_threshold=0.05, device="cpu")
    print(f"      Initialized successfully on: {registry.device}")
    
    # 2. Load safe baselines
    print("\n[2/4] Loading and registering safe baseline tool schemas...")
    with open("safe_baselines.json", "r") as f:
        safe_tools = json.load(f)
        
    for tool in safe_tools:
        registry.register_baseline(tool)
    print(f"      Successfully registered {len(safe_tools)} tools in the FAISS index.")
    
    # 3. Load poisoned/adversarial data templates
    with open("poisoned_tests.json", "r") as f:
        poisoned_tools = json.load(f)
        
    # 4. Run Benchmark
    print("\n[3/4] Running shadow attack detection evaluation...")
    
    # Suppress verbose warnings to ensure clean summary logs
    import logging
    logging.getLogger("mcp_vector_shield").setLevel(logging.ERROR)
    
    # Test case A: Identical Tools (should be safe)
    identical_count = 0
    identical_flagged = 0
    for tool in safe_tools:
        identical_count += 1
        if registry.is_shadowing_attack(tool):
            identical_flagged += 1
            
    # Test case B: Minor Safe Updates (should be safe)
    safe_update_count = 0
    safe_update_flagged = 0
    for tool in safe_tools:
        safe_update_count += 1
        # Create a minor harmless update
        modified_tool = {
            "name": tool["name"],
            "description": tool["description"] + " Updated with standard performance optimizations.",
            "inputSchema": tool["inputSchema"]
        }
        if registry.is_shadowing_attack(modified_tool):
            safe_update_flagged += 1
            
    # Test case C: Shadowing Attacks (same name, poisoned description)
    shadow_attack_count = 0
    shadow_attack_flagged = 0
    for shadowed_tool in poisoned_tools:
        shadow_attack_count += 1
        if registry.is_shadowing_attack(shadowed_tool):
            shadow_attack_flagged += 1
            
    # 5. Output Summary Results
    print("\n" + "=" * 70)
    print("                          BENCHMARK SUMMARY                           ")
    print("=" * 70)
    
    print(f"  A. Identical Baseline Tests:")
    print(f"     - Evaluated: {identical_count}")
    print(f"     - Flagged as Shadow Attack: {identical_flagged} (Expected: 0)")
    print(f"     - False Positive Rate: {identical_flagged/identical_count*100:.1f}%")
    
    print(f"\n  B. Safe Minor Update Tests:")
    print(f"     - Evaluated: {safe_update_count}")
    print(f"     - Flagged as Shadow Attack: {safe_update_flagged} (Expected: 0)")
    print(f"     - False Positive Rate: {safe_update_flagged/safe_update_count*100:.1f}%")
    
    print(f"\n  C. Poisoned Shadowing Attack Tests:")
    print(f"     - Evaluated: {shadow_attack_count}")
    print(f"     - Flagged as Shadow Attack: {shadow_attack_flagged} (Expected: {shadow_attack_count})")
    print(f"     - Detection Success Rate: {shadow_attack_flagged/shadow_attack_count*100:.1f}%")
    
    # Overall Accuracy
    total_evals = identical_count + safe_update_count + shadow_attack_count
    correct_classifications = (identical_count - identical_flagged) + (safe_update_count - safe_update_flagged) + shadow_attack_flagged
    accuracy = correct_classifications / total_evals * 100
    
    print("-" * 70)
    print(f"  OVERALL DETECTOR ACCURACY: {accuracy:.2f}%")
    print("=" * 70)

if __name__ == "__main__":
    main()
