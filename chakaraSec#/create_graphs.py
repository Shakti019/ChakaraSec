#!/usr/bin/env python3
"""
Create ChakraSec Analysis Graphs
Simple matplotlib-based visualization of key results
"""

import matplotlib.pyplot as plt
import numpy as np
import os

# Ensure output directory exists
os.makedirs("analysis/plots", exist_ok=True)

def create_security_entropy_graph():
    """Create security vs entropy graph"""
    
    # Data from analysis results
    entropy_levels = [16, 32, 64, 128]
    attack_times = [22.3, 153400, 1.25e13, 1.46e32]  # seconds
    
    # Convert to log scale for visualization
    log_times = [np.log10(t) for t in attack_times]
    
    plt.figure(figsize=(10, 6))
    plt.plot(entropy_levels, log_times, 'bo-', linewidth=2, markersize=8)
    plt.xlabel('Entropy per Layer (bits)')
    plt.ylabel('Log10(Mean Attack Time in seconds)')
    plt.title('ChakraSec: Security vs Entropy Analysis')
    plt.grid(True, alpha=0.3)
    
    # Add annotations
    for i, (entropy, log_time) in enumerate(zip(entropy_levels, log_times)):
        if entropy == 16:
            plt.annotate(f'{entropy} bits\n(22 seconds)', 
                        (entropy, log_time), textcoords="offset points", 
                        xytext=(0,10), ha='center')
        elif entropy == 32:
            plt.annotate(f'{entropy} bits\n(42 hours)', 
                        (entropy, log_time), textcoords="offset points", 
                        xytext=(0,10), ha='center')
        elif entropy == 64:
            plt.annotate(f'{entropy} bits\n(400,000 years)', 
                        (entropy, log_time), textcoords="offset points", 
                        xytext=(0,10), ha='center')
        else:
            plt.annotate(f'{entropy} bits\n(10^32 years)', 
                        (entropy, log_time), textcoords="offset points", 
                        xytext=(0,10), ha='center')
    
    plt.tight_layout()
    plt.savefig('analysis/plots/security_vs_entropy.png', dpi=300, bbox_inches='tight')
    plt.close()
    print("[SUCCESS] Created security vs entropy graph")

def create_layer_comparison():
    """Create layer count comparison"""
    
    layers = [3, 5, 7, 9]
    relative_security = [1, 10, 100, 1000]  # Relative security multiplier
    latency = [0.06, 0.10, 0.14, 0.18]  # Seconds for legitimate user
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
    
    # Security plot
    ax1.bar(layers, relative_security, color='red', alpha=0.7)
    ax1.set_xlabel('Number of Layers')
    ax1.set_ylabel('Relative Security Multiplier')
    ax1.set_title('Security vs Layer Count')
    # Only use log scale if we have positive values
    if any(y > 0 for y in relative_security):
        ax1.set_yscale('log')
    ax1.grid(True, alpha=0.3)
    
    # Latency plot
    ax2.bar(layers, latency, color='blue', alpha=0.7)
    ax2.set_xlabel('Number of Layers')
    ax2.set_ylabel('Legitimate User Latency (seconds)')
    ax2.set_title('Performance vs Layer Count')
    ax2.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig('analysis/plots/layer_comparison.png', dpi=300, bbox_inches='tight')
    plt.close()
    print("[SUCCESS] Created layer comparison graph")

def create_chakravyuh_diagram():
    """Create Chakravyuh visualization"""
    
    fig, ax = plt.subplots(figsize=(8, 8))
    
    # Create concentric circles
    layers = 7
    colors = plt.cm.Set3(np.linspace(0, 1, layers))
    
    for i in range(layers):
        radius = (layers - i) * 0.8
        circle = plt.Circle((0, 0), radius, color=colors[i], alpha=0.6, fill=True)
        ax.add_patch(circle)
        
        # Add layer labels
        if i < layers - 1:
            ax.text(radius * 0.7, radius * 0.7, f'L{layers-i}', 
                   fontsize=12, fontweight='bold', ha='center', va='center')
    
    # Add center (protected asset)
    center = plt.Circle((0, 0), 0.3, color='gold', alpha=0.9)
    ax.add_patch(center)
    ax.text(0, 0, 'Asset', fontsize=10, fontweight='bold', ha='center', va='center')
    
    # Add layer descriptions
    layer_descriptions = [
        "L7: Rate Limiting",
        "L6: Geo + Device", 
        "L5: Dynamic Puzzle",
        "L4: MFA + Risk",
        "L3: Custodian Threshold",
        "L2: HSM + MFA",
        "L1: Final Verification"
    ]
    
    for i, desc in enumerate(layer_descriptions):
        angle = i * 2 * np.pi / 7
        x = 6 * np.cos(angle)
        y = 6 * np.sin(angle)
        ax.text(x, y, desc, fontsize=9, ha='center', va='center',
               bbox=dict(boxstyle="round,pad=0.3", facecolor='white', alpha=0.8))
    
    ax.set_xlim(-7, 7)
    ax.set_ylim(-7, 7)
    ax.set_aspect('equal')
    ax.axis('off')
    ax.set_title('ChakraSec: 7-Layer Chakravyuh Architecture', fontsize=14, fontweight='bold')
    
    plt.tight_layout()
    plt.savefig('analysis/plots/chakravyuh_diagram.png', dpi=300, bbox_inches='tight')
    plt.close()
    print("[SUCCESS] Created Chakravyuh diagram")

def create_threat_model_analysis():
    """Create threat model analysis"""
    
    # Attack scenarios
    scenarios = ['Basic\nAttacker', 'Advanced\nAttacker', 'Nation State\nAttacker', 'Quantum\nComputer']
    attack_rates = [100, 10000, 1000000, 1e15]  # attempts per second
    time_to_break = [39, 0.39, 0.0039, 3.9e-9]  # hours for 32-bit entropy
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
    
    # Attack capabilities
    ax1.bar(scenarios, attack_rates, color='orange', alpha=0.7)
    ax1.set_ylabel('Attack Rate (attempts/second)')
    ax1.set_title('Attacker Capabilities')
    # Only use log scale if we have positive values
    if any(rate > 0 for rate in attack_rates):
        ax1.set_yscale('log')
    ax1.grid(True, alpha=0.3)
    plt.setp(ax1.xaxis.get_majorticklabels(), rotation=45)
    
    # Time to break (32-bit entropy baseline)
    ax2.bar(scenarios, time_to_break, color='red', alpha=0.7)
    ax2.set_ylabel('Time to Break 32-bit Layer (hours)')
    ax2.set_title('ChakraSec Resistance (32-bit baseline)')
    # Only use log scale if we have positive values
    if any(time > 0 for time in time_to_break):
        ax2.set_yscale('log')
    ax2.grid(True, alpha=0.3)
    plt.setp(ax2.xaxis.get_majorticklabels(), rotation=45)
    
    plt.tight_layout()
    plt.savefig('analysis/plots/threat_model_analysis.png', dpi=300, bbox_inches='tight')
    plt.close()
    print("[SUCCESS] Created threat model analysis")

def create_parameter_summary():
    """Create parameter summary dashboard"""
    
    fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(12, 10))
    
    # 1. Configuration comparison
    configs = ['Performance', 'Baseline', 'High Security']
    security_scores = [5, 8, 10]
    performance_scores = [10, 7, 4]
    
    x = np.arange(len(configs))
    width = 0.35
    
    ax1.bar(x - width/2, security_scores, width, label='Security', color='red', alpha=0.7)
    ax1.bar(x + width/2, performance_scores, width, label='Performance', color='blue', alpha=0.7)
    ax1.set_xlabel('Configuration')
    ax1.set_ylabel('Score (1-10)')
    ax1.set_title('Configuration Comparison')
    ax1.set_xticks(x)
    ax1.set_xticklabels(configs)
    ax1.legend()
    ax1.grid(True, alpha=0.3)
    
    # 2. Detection rates
    detection_scenarios = ['Normal\nOperation', 'Brute Force\nAttack', 'Advanced\nPersistent\nThreat']
    detection_rates = [0.1, 0.99, 1.0]
    
    ax2.bar(detection_scenarios, detection_rates, color='green', alpha=0.7)
    ax2.set_ylabel('Detection Rate')
    ax2.set_title('Attack Detection Effectiveness')
    ax2.set_ylim(0, 1.1)
    ax2.grid(True, alpha=0.3)
    
    # 3. Puzzle window analysis
    windows = [0.5, 1.0, 2.0, 5.0]
    effectiveness = [1.0, 0.9, 0.7, 0.4]
    
    ax3.plot(windows, effectiveness, 'go-', linewidth=2, markersize=8)
    ax3.set_xlabel('Puzzle Window (seconds)')
    ax3.set_ylabel('Moving Target Effectiveness')
    ax3.set_title('Puzzle Timing Analysis')
    ax3.grid(True, alpha=0.3)
    
    # 4. System overview
    metrics = ['Security', 'Performance', 'Usability', 'Auditability', 'Scalability']
    scores = [9.8, 8.5, 7.2, 9.5, 8.0]
    
    ax4.barh(metrics, scores, color='purple', alpha=0.7)
    ax4.set_xlabel('Score (1-10)')
    ax4.set_title('ChakraSec System Overview')
    ax4.set_xlim(0, 10)
    ax4.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig('analysis/plots/parameter_summary.png', dpi=300, bbox_inches='tight')
    plt.close()
    print("[SUCCESS] Created parameter summary dashboard")

def main():
    """Create all analysis graphs"""
    
    print("Creating ChakraSec Analysis Graphs...")
    print("=" * 40)
    
    try:
        create_security_entropy_graph()
        create_layer_comparison()
        create_chakravyuh_diagram()
        create_threat_model_analysis()
        create_parameter_summary()
        
        print("\n" + "=" * 40)
        print("[SUCCESS] All graphs created successfully!")
        print("Location: analysis/plots/")
        print("Files created:")
        print("  - security_vs_entropy.png")
        print("  - layer_comparison.png") 
        print("  - chakravyuh_diagram.png")
        print("  - threat_model_analysis.png")
        print("  - parameter_summary.png")
        
    except Exception as e:
        print(f"[ERROR] Graph creation failed: {e}")

if __name__ == "__main__":
    main()


