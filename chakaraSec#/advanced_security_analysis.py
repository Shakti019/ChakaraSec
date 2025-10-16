#!/usr/bin/env python3
"""
Advanced Statistical Security Analysis for ChakraSec
Implements advanced statistical models, machine learning approaches, and comprehensive visualization
"""

import os
import sys
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
from pathlib import Path
import time
import logging
from scipy import stats
from scipy.optimize import curve_fit
from sklearn.ensemble import RandomForestRegressor
from sklearn.model_selection import cross_val_score
from sklearn.preprocessing import StandardScaler
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import warnings
warnings.filterwarnings('ignore')

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Output directory
OUTPUT_DIR = Path("analysis/results/advanced_analysis")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

class AdvancedSecurityModel:
    """Advanced statistical security model for ChakraSec"""
    
    def __init__(self, n_samples=10000):
        self.n_samples = n_samples
        self.data = None
        self.ml_model = None
        
    def generate_synthetic_data(self):
        """Generate synthetic security data based on ChakraSec parameters"""
        logger.info(f"Generating {self.n_samples} synthetic security samples...")
        
        np.random.seed(42)
        
        # Security parameters
        n_layers = np.random.choice([3, 5, 7, 9], self.n_samples)
        entropy_bits = np.random.choice([16, 32, 64, 128, 256], self.n_samples)
        puzzle_entropy = np.random.choice([32, 64, 128, 256], self.n_samples)
        puzzle_window = np.random.uniform(0.5, 5.0, self.n_samples)
        custodian_threshold = np.random.randint(2, 6, self.n_samples)
        custodian_total = custodian_threshold + np.random.randint(1, 4, self.n_samples)
        
        # Attacker capabilities
        attack_speed = np.random.uniform(100, 10000, self.n_samples)
        parallel_bots = np.random.randint(10, 1000, self.n_samples)
        compute_factor = np.random.uniform(1, 100, self.n_samples)
        
        # Calculate security metrics
        # Time to break (exponential relationship with entropy)
        base_time = 2 ** (entropy_bits / 8)
        layer_multiplier = n_layers ** 2
        puzzle_factor = 2 ** (puzzle_entropy / 16)
        attacker_factor = attack_speed * parallel_bots * compute_factor / 1e6
        
        time_to_break = (base_time * layer_multiplier * puzzle_factor) / attacker_factor
        time_to_break *= np.random.lognormal(0, 0.3, self.n_samples)  # Add realistic variation
        
        # Attack success probability (inverse relationship with security)
        base_success = 1.0 / (1 + np.exp((entropy_bits - 64) / 16))
        layer_factor = np.exp(-0.3 * n_layers)
        puzzle_factor = 1.0 / (1 + puzzle_entropy / 64)
        
        attack_success = base_success * layer_factor * puzzle_factor
        attack_success = np.clip(attack_success + np.random.normal(0, 0.05, self.n_samples), 0, 1)
        
        # Detection rate (higher with more layers and lower window)
        detection_rate = 1 - (1.0 / (1 + np.exp((n_layers - 5) / 2)))
        detection_rate *= (1.0 / (1 + puzzle_window / 2))
        detection_rate = np.clip(detection_rate + np.random.normal(0, 0.05, self.n_samples), 0, 1)
        
        # Legitimate user latency (linear with layers)
        latency = 0.02 * n_layers + 0.01 * puzzle_entropy / 64
        latency += np.random.normal(0, 0.005, self.n_samples)
        latency = np.maximum(latency, 0.01)
        
        # Defense effectiveness (combined metric)
        defense_effectiveness = (1 - attack_success) * detection_rate
        
        # Security score (0-100)
        security_score = (
            (entropy_bits / 256) * 30 +
            (n_layers / 9) * 25 +
            (puzzle_entropy / 256) * 25 +
            detection_rate * 20
        )
        
        self.data = pd.DataFrame({
            'n_layers': n_layers,
            'entropy_bits': entropy_bits,
            'puzzle_entropy': puzzle_entropy,
            'puzzle_window': puzzle_window,
            'custodian_threshold': custodian_threshold,
            'custodian_total': custodian_total,
            'attack_speed': attack_speed,
            'parallel_bots': parallel_bots,
            'compute_factor': compute_factor,
            'time_to_break': time_to_break,
            'attack_success': attack_success,
            'detection_rate': detection_rate,
            'latency': latency,
            'defense_effectiveness': defense_effectiveness,
            'security_score': security_score
        })
        
        logger.info(f"Generated dataset shape: {self.data.shape}")
        return self.data
    
    def train_ml_model(self):
        """Train machine learning model to predict security metrics"""
        logger.info("Training Random Forest model...")
        
        # Features
        features = ['n_layers', 'entropy_bits', 'puzzle_entropy', 'puzzle_window',
                   'custodian_threshold', 'attack_speed', 'parallel_bots', 'compute_factor']
        X = self.data[features]
        
        # Target: security score
        y = self.data['security_score']
        
        # Train model
        self.ml_model = RandomForestRegressor(n_estimators=100, random_state=42, max_depth=10)
        self.ml_model.fit(X, y)
        
        # Cross-validation
        cv_scores = cross_val_score(self.ml_model, X, y, cv=5, scoring='r2')
        logger.info(f"ML Model R² Score: {cv_scores.mean():.3f} (+/- {cv_scores.std():.3f})")
        
        # Feature importance
        feature_importance = pd.DataFrame({
            'feature': features,
            'importance': self.ml_model.feature_importances_
        }).sort_values('importance', ascending=False)
        
        logger.info("\nFeature Importance:")
        for _, row in feature_importance.iterrows():
            logger.info(f"  {row['feature']:20s}: {row['importance']:.4f}")
        
        return self.ml_model, feature_importance
    
    def statistical_analysis(self):
        """Perform advanced statistical analysis"""
        logger.info("Performing statistical analysis...")
        
        results = {}
        
        # 1. Correlation analysis
        corr_matrix = self.data.corr()
        results['correlation'] = corr_matrix
        
        # 2. Entropy effect on time to break (power law fit)
        entropy_values = np.unique(self.data['entropy_bits'])
        mean_times = []
        std_times = []
        
        for entropy in entropy_values:
            subset = self.data[self.data['entropy_bits'] == entropy]['time_to_break']
            mean_times.append(subset.mean())
            std_times.append(subset.std())
        
        # Fit power law: y = a * x^b
        def power_law(x, a, b):
            return a * np.power(x, b)
        
        try:
            popt, pcov = curve_fit(power_law, entropy_values, mean_times)
            results['power_law_params'] = {'a': popt[0], 'b': popt[1]}
            logger.info(f"Power law fit: time = {popt[0]:.2e} * entropy^{popt[1]:.2f}")
        except:
            results['power_law_params'] = None
        
        # 3. Layer count distribution analysis
        layer_stats = self.data.groupby('n_layers').agg({
            'attack_success': ['mean', 'std'],
            'detection_rate': ['mean', 'std'],
            'time_to_break': ['mean', 'median', 'std'],
            'security_score': ['mean', 'std']
        })
        results['layer_statistics'] = layer_stats
        
        # 4. Risk analysis (attack success vs security parameters)
        high_risk = self.data[self.data['attack_success'] > 0.5]
        low_risk = self.data[self.data['attack_success'] <= 0.1]
        
        results['risk_analysis'] = {
            'high_risk_count': len(high_risk),
            'low_risk_count': len(low_risk),
            'high_risk_mean_layers': high_risk['n_layers'].mean(),
            'low_risk_mean_layers': low_risk['n_layers'].mean(),
            'high_risk_mean_entropy': high_risk['entropy_bits'].mean(),
            'low_risk_mean_entropy': low_risk['entropy_bits'].mean()
        }
        
        logger.info(f"\nRisk Analysis:")
        logger.info(f"  High risk configs (>50% attack success): {len(high_risk)}")
        logger.info(f"  Low risk configs (<10% attack success): {len(low_risk)}")
        
        return results

def create_advanced_visualizations(model, stats_results):
    """Create comprehensive advanced visualizations"""
    logger.info("Creating advanced visualizations...")
    
    data = model.data
    
    # Set style
    sns.set_style("whitegrid")
    plt.rcParams['figure.dpi'] = 300
    
    # ============= 1. Correlation Heatmap =============
    fig, ax = plt.subplots(figsize=(14, 12))
    
    # Select key variables for correlation
    corr_vars = ['n_layers', 'entropy_bits', 'puzzle_entropy', 'puzzle_window',
                 'attack_speed', 'time_to_break', 'attack_success', 'detection_rate',
                 'defense_effectiveness', 'security_score']
    corr_data = data[corr_vars].corr()
    
    sns.heatmap(corr_data, annot=True, fmt='.2f', cmap='RdYlGn', center=0,
                square=True, linewidths=0.5, cbar_kws={"shrink": 0.8}, ax=ax)
    ax.set_title('Advanced Correlation Matrix - ChakraSec Security Parameters', fontsize=16, pad=20)
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / 'correlation_heatmap.png', dpi=300, bbox_inches='tight')
    plt.close()
    logger.info("✓ Created correlation heatmap")
    
    # ============= 2. 3D Security Surface Plot =============
    fig = plt.figure(figsize=(14, 10))
    ax = fig.add_subplot(111, projection='3d')
    
    # Sample data for 3D plot
    sample_data = data.sample(min(2000, len(data)))
    
    scatter = ax.scatter(sample_data['n_layers'], 
                        sample_data['entropy_bits'],
                        sample_data['security_score'],
                        c=sample_data['attack_success'],
                        cmap='RdYlGn_r',
                        s=50,
                        alpha=0.6)
    
    ax.set_xlabel('Number of Layers', fontsize=12, labelpad=10)
    ax.set_ylabel('Entropy Bits', fontsize=12, labelpad=10)
    ax.set_zlabel('Security Score', fontsize=12, labelpad=10)
    ax.set_title('3D Security Landscape\nColor: Attack Success Rate', fontsize=14, pad=20)
    
    cbar = plt.colorbar(scatter, ax=ax, shrink=0.5, aspect=5)
    cbar.set_label('Attack Success Rate', rotation=270, labelpad=20)
    
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / 'security_3d_surface.png', dpi=300, bbox_inches='tight')
    plt.close()
    logger.info("✓ Created 3D security surface plot")
    
    # ============= 3. Distribution Analysis =============
    fig, axes = plt.subplots(2, 3, figsize=(18, 12))
    
    # Time to break distribution
    axes[0, 0].hist(np.log10(data['time_to_break']), bins=50, edgecolor='black', alpha=0.7, color='steelblue')
    axes[0, 0].set_xlabel('Log10(Time to Break) [seconds]', fontsize=11)
    axes[0, 0].set_ylabel('Frequency', fontsize=11)
    axes[0, 0].set_title('Distribution: Time to Break', fontsize=12, fontweight='bold')
    axes[0, 0].grid(True, alpha=0.3)
    
    # Attack success distribution
    axes[0, 1].hist(data['attack_success'], bins=50, edgecolor='black', alpha=0.7, color='crimson')
    axes[0, 1].set_xlabel('Attack Success Probability', fontsize=11)
    axes[0, 1].set_ylabel('Frequency', fontsize=11)
    axes[0, 1].set_title('Distribution: Attack Success Rate', fontsize=12, fontweight='bold')
    axes[0, 1].grid(True, alpha=0.3)
    
    # Detection rate distribution
    axes[0, 2].hist(data['detection_rate'], bins=50, edgecolor='black', alpha=0.7, color='forestgreen')
    axes[0, 2].set_xlabel('Detection Rate', fontsize=11)
    axes[0, 2].set_ylabel('Frequency', fontsize=11)
    axes[0, 2].set_title('Distribution: Attack Detection Rate', fontsize=12, fontweight='bold')
    axes[0, 2].grid(True, alpha=0.3)
    
    # Security score distribution
    axes[1, 0].hist(data['security_score'], bins=50, edgecolor='black', alpha=0.7, color='darkorange')
    axes[1, 0].set_xlabel('Security Score', fontsize=11)
    axes[1, 0].set_ylabel('Frequency', fontsize=11)
    axes[1, 0].set_title('Distribution: Security Score', fontsize=12, fontweight='bold')
    axes[1, 0].grid(True, alpha=0.3)
    
    # Layer count vs security
    layer_security = data.groupby('n_layers')['security_score'].mean()
    axes[1, 1].bar(layer_security.index, layer_security.values, edgecolor='black', alpha=0.7, color='mediumpurple')
    axes[1, 1].set_xlabel('Number of Layers', fontsize=11)
    axes[1, 1].set_ylabel('Mean Security Score', fontsize=11)
    axes[1, 1].set_title('Security Score by Layer Count', fontsize=12, fontweight='bold')
    axes[1, 1].grid(True, alpha=0.3, axis='y')
    
    # Entropy vs security
    entropy_security = data.groupby('entropy_bits')['security_score'].mean()
    axes[1, 2].plot(entropy_security.index, entropy_security.values, 'o-', linewidth=2, markersize=8, color='teal')
    axes[1, 2].set_xlabel('Entropy Bits per Layer', fontsize=11)
    axes[1, 2].set_ylabel('Mean Security Score', fontsize=11)
    axes[1, 2].set_title('Security Score by Entropy', fontsize=12, fontweight='bold')
    axes[1, 2].grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / 'distribution_analysis.png', dpi=300, bbox_inches='tight')
    plt.close()
    logger.info("✓ Created distribution analysis")
    
    # ============= 4. Advanced Regression Analysis =============
    fig, axes = plt.subplots(2, 2, figsize=(16, 12))
    
    # Entropy vs Time to Break (log-log)
    for layer in [3, 5, 7, 9]:
        subset = data[data['n_layers'] == layer]
        entropy_groups = subset.groupby('entropy_bits')['time_to_break'].mean()
        axes[0, 0].plot(entropy_groups.index, entropy_groups.values, 'o-', 
                       label=f'{layer} layers', linewidth=2, markersize=6)
    
    axes[0, 0].set_xlabel('Entropy Bits', fontsize=12)
    axes[0, 0].set_ylabel('Mean Time to Break (seconds)', fontsize=12)
    axes[0, 0].set_title('Time to Break vs Entropy\n(by Layer Count)', fontsize=13, fontweight='bold')
    axes[0, 0].set_yscale('log')
    axes[0, 0].set_xscale('log')
    axes[0, 0].legend()
    axes[0, 0].grid(True, alpha=0.3, which='both')
    
    # Layer count vs Attack Success
    layer_attack = data.groupby('n_layers').agg({
        'attack_success': ['mean', 'std']
    })
    
    axes[0, 1].errorbar(layer_attack.index, 
                       layer_attack[('attack_success', 'mean')],
                       yerr=layer_attack[('attack_success', 'std')],
                       fmt='o-', linewidth=2, markersize=8, capsize=5, color='crimson')
    axes[0, 1].set_xlabel('Number of Layers', fontsize=12)
    axes[0, 1].set_ylabel('Attack Success Probability', fontsize=12)
    axes[0, 1].set_title('Attack Success vs Layer Count\n(with std deviation)', fontsize=13, fontweight='bold')
    axes[0, 1].grid(True, alpha=0.3)
    
    # Puzzle window vs Detection Rate
    window_bins = pd.cut(data['puzzle_window'], bins=10)
    window_detection = data.groupby(window_bins)['detection_rate'].mean()
    window_centers = [interval.mid for interval in window_detection.index]
    
    axes[1, 0].plot(window_centers, window_detection.values, 'o-', 
                   linewidth=2, markersize=8, color='forestgreen')
    axes[1, 0].set_xlabel('Puzzle Window (seconds)', fontsize=12)
    axes[1, 0].set_ylabel('Detection Rate', fontsize=12)
    axes[1, 0].set_title('Detection Rate vs Puzzle Window', fontsize=13, fontweight='bold')
    axes[1, 0].grid(True, alpha=0.3)
    
    # Security Score vs Defense Effectiveness
    axes[1, 1].hexbin(data['security_score'], data['defense_effectiveness'], 
                     gridsize=30, cmap='YlOrRd', mincnt=1)
    axes[1, 1].set_xlabel('Security Score', fontsize=12)
    axes[1, 1].set_ylabel('Defense Effectiveness', fontsize=12)
    axes[1, 1].set_title('Security Score vs Defense Effectiveness\n(density plot)', 
                        fontsize=13, fontweight='bold')
    
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / 'regression_analysis.png', dpi=300, bbox_inches='tight')
    plt.close()
    logger.info("✓ Created regression analysis")
    
    # ============= 5. Feature Importance (ML Model) =============
    if model.ml_model is not None:
        fig, ax = plt.subplots(figsize=(10, 8))
        
        features = ['n_layers', 'entropy_bits', 'puzzle_entropy', 'puzzle_window',
                   'custodian_threshold', 'attack_speed', 'parallel_bots', 'compute_factor']
        importances = model.ml_model.feature_importances_
        
        # Sort by importance
        indices = np.argsort(importances)[::-1]
        
        ax.barh(range(len(features)), importances[indices], color='steelblue', edgecolor='black', alpha=0.7)
        ax.set_yticks(range(len(features)))
        ax.set_yticklabels([features[i] for i in indices])
        ax.set_xlabel('Feature Importance', fontsize=12)
        ax.set_title('Random Forest Feature Importance\nPredicting Security Score', 
                    fontsize=14, fontweight='bold')
        ax.grid(True, alpha=0.3, axis='x')
        
        # Add values on bars
        for i, v in enumerate(importances[indices]):
            ax.text(v + 0.005, i, f'{v:.3f}', va='center', fontsize=10)
        
        plt.tight_layout()
        plt.savefig(OUTPUT_DIR / 'feature_importance.png', dpi=300, bbox_inches='tight')
        plt.close()
        logger.info("✓ Created feature importance plot")
    
    # ============= 6. ROC-style Analysis =============
    fig, axes = plt.subplots(1, 2, figsize=(16, 6))
    
    # Security vs Performance Trade-off
    axes[0].scatter(data['latency'], data['security_score'], 
                   c=data['n_layers'], cmap='viridis', s=20, alpha=0.6)
    axes[0].set_xlabel('Legitimate User Latency (seconds)', fontsize=12)
    axes[0].set_ylabel('Security Score', fontsize=12)
    axes[0].set_title('Security-Performance Trade-off\n(color: layer count)', 
                     fontsize=13, fontweight='bold')
    axes[0].grid(True, alpha=0.3)
    
    cbar = plt.colorbar(axes[0].collections[0], ax=axes[0])
    cbar.set_label('Number of Layers', rotation=270, labelpad=20)
    
    # Attack Success vs Detection Rate
    axes[1].scatter(data['attack_success'], data['detection_rate'],
                   c=data['security_score'], cmap='RdYlGn', s=20, alpha=0.6)
    axes[1].set_xlabel('Attack Success Probability', fontsize=12)
    axes[1].set_ylabel('Detection Rate', fontsize=12)
    axes[1].set_title('Attack Success vs Detection\n(color: security score)', 
                     fontsize=13, fontweight='bold')
    axes[1].grid(True, alpha=0.3)
    
    # Add diagonal line for reference
    axes[1].plot([0, 1], [1, 0], 'r--', linewidth=2, alpha=0.7, label='Ideal Defense')
    axes[1].legend()
    
    cbar = plt.colorbar(axes[1].collections[0], ax=axes[1])
    cbar.set_label('Security Score', rotation=270, labelpad=20)
    
    plt.tight_layout()
    plt.savefig(OUTPUT_DIR / 'tradeoff_analysis.png', dpi=300, bbox_inches='tight')
    plt.close()
    logger.info("✓ Created trade-off analysis")

def create_interactive_plotly_visualizations(model):
    """Create interactive Plotly visualizations"""
    logger.info("Creating interactive Plotly visualizations...")
    
    data = model.data
    
    # ============= 1. Interactive 3D Scatter =============
    fig = go.Figure(data=[go.Scatter3d(
        x=data['n_layers'],
        y=data['entropy_bits'],
        z=data['security_score'],
        mode='markers',
        marker=dict(
            size=3,
            color=data['attack_success'],
            colorscale='RdYlGn_r',
            showscale=True,
            colorbar=dict(title="Attack<br>Success"),
            opacity=0.6
        ),
        text=[f'Layers: {l}<br>Entropy: {e}<br>Score: {s:.1f}<br>Attack Success: {a:.3f}'
              for l, e, s, a in zip(data['n_layers'], data['entropy_bits'], 
                                   data['security_score'], data['attack_success'])],
        hoverinfo='text'
    )])
    
    fig.update_layout(
        title='Interactive 3D Security Landscape',
        scene=dict(
            xaxis_title='Number of Layers',
            yaxis_title='Entropy Bits',
            zaxis_title='Security Score'
        ),
        width=1000,
        height=800
    )
    
    fig.write_html(OUTPUT_DIR / 'interactive_3d_security.html')
    logger.info("✓ Created interactive 3D visualization")
    
    # ============= 2. Interactive Dashboard =============
    fig = make_subplots(
        rows=2, cols=2,
        subplot_titles=('Time to Break by Configuration', 
                       'Attack Success Distribution',
                       'Security Score by Parameters',
                       'Detection Rate Analysis'),
        specs=[[{'type': 'box'}, {'type': 'histogram'}],
               [{'type': 'scatter'}, {'type': 'violin'}]]
    )
    
    # Box plot - Time to break by layers
    for layer in sorted(data['n_layers'].unique()):
        subset = data[data['n_layers'] == layer]
        fig.add_trace(
            go.Box(y=np.log10(subset['time_to_break']), name=f'{layer} layers'),
            row=1, col=1
        )
    
    # Histogram - Attack success
    fig.add_trace(
        go.Histogram(x=data['attack_success'], nbinsx=50, name='Attack Success'),
        row=1, col=2
    )
    
    # Scatter - Entropy vs Security Score
    fig.add_trace(
        go.Scatter(x=data['entropy_bits'], y=data['security_score'],
                  mode='markers', marker=dict(size=4, opacity=0.5),
                  name='Entropy vs Security'),
        row=2, col=1
    )
    
    # Violin plot - Detection rate by layer
    for layer in sorted(data['n_layers'].unique()):
        subset = data[data['n_layers'] == layer]
        fig.add_trace(
            go.Violin(y=subset['detection_rate'], name=f'{layer} layers'),
            row=2, col=2
        )
    
    fig.update_layout(height=800, width=1200, title_text="ChakraSec Interactive Analysis Dashboard")
    fig.write_html(OUTPUT_DIR / 'interactive_dashboard.html')
    logger.info("✓ Created interactive dashboard")
    
    # ============= 3. Time Series Attack Simulation =============
    # Simulate attack over time
    time_steps = 100
    attack_progress = []
    
    for config_id in range(5):
        layers = np.random.choice([3, 5, 7, 9])
        entropy = np.random.choice([32, 64, 128])
        
        # Simulate progressive attack
        progress = []
        for t in range(time_steps):
            # Probability of breaching layer increases with time
            prob = 1 - np.exp(-t / (layers * entropy / 10))
            prob += np.random.normal(0, 0.02)
            progress.append(np.clip(prob, 0, 1))
        
        attack_progress.append({
            'config': f'{layers}L-{entropy}b',
            'progress': progress
        })
    
    fig = go.Figure()
    
    for attack in attack_progress:
        fig.add_trace(go.Scatter(
            x=list(range(time_steps)),
            y=attack['progress'],
            mode='lines',
            name=attack['config'],
            line=dict(width=2)
        ))
    
    fig.update_layout(
        title='Simulated Attack Progress Over Time',
        xaxis_title='Time Steps',
        yaxis_title='Attack Progress (normalized)',
        width=1000,
        height=600
    )
    
    fig.write_html(OUTPUT_DIR / 'attack_simulation.html')
    logger.info("✓ Created attack simulation")

def generate_statistical_report(model, stats_results):
    """Generate comprehensive statistical report"""
    logger.info("Generating statistical report...")
    
    report_path = OUTPUT_DIR / 'statistical_report.txt'
    
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write("="*80 + "\n")
        f.write("CHAKRASEC ADVANCED STATISTICAL SECURITY ANALYSIS REPORT\n")
        f.write("="*80 + "\n\n")
        
        f.write(f"Analysis Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total Samples Analyzed: {len(model.data):,}\n\n")
        
        # Summary Statistics
        f.write("-"*80 + "\n")
        f.write("1. SUMMARY STATISTICS\n")
        f.write("-"*80 + "\n\n")
        
        summary_stats = model.data.describe()
        f.write(summary_stats.to_string())
        f.write("\n\n")
        
        # Security Metrics
        f.write("-"*80 + "\n")
        f.write("2. SECURITY METRICS ANALYSIS\n")
        f.write("-"*80 + "\n\n")
        
        f.write(f"Mean Time to Break: {model.data['time_to_break'].mean():.2e} seconds\n")
        f.write(f"Median Time to Break: {model.data['time_to_break'].median():.2e} seconds\n")
        f.write(f"Mean Attack Success Rate: {model.data['attack_success'].mean():.4f}\n")
        f.write(f"Mean Detection Rate: {model.data['detection_rate'].mean():.4f}\n")
        f.write(f"Mean Security Score: {model.data['security_score'].mean():.2f}/100\n\n")
        
        # Configuration Analysis
        f.write("-"*80 + "\n")
        f.write("3. CONFIGURATION ANALYSIS\n")
        f.write("-"*80 + "\n\n")
        
        # Best configurations
        top_5 = model.data.nlargest(5, 'security_score')[
            ['n_layers', 'entropy_bits', 'puzzle_entropy', 'security_score', 'attack_success']
        ]
        f.write("Top 5 Most Secure Configurations:\n")
        f.write(top_5.to_string(index=False))
        f.write("\n\n")
        
        # Layer analysis
        f.write("Security by Layer Count:\n")
        layer_analysis = model.data.groupby('n_layers').agg({
            'security_score': 'mean',
            'attack_success': 'mean',
            'detection_rate': 'mean',
            'time_to_break': 'mean'
        })
        f.write(layer_analysis.to_string())
        f.write("\n\n")
        
        # Risk Analysis
        f.write("-"*80 + "\n")
        f.write("4. RISK ANALYSIS\n")
        f.write("-"*80 + "\n\n")
        
        risk_info = stats_results.get('risk_analysis', {})
        f.write(f"High Risk Configurations (>50% attack success): {risk_info.get('high_risk_count', 0)}\n")
        f.write(f"  - Mean Layers: {risk_info.get('high_risk_mean_layers', 0):.2f}\n")
        f.write(f"  - Mean Entropy: {risk_info.get('high_risk_mean_entropy', 0):.2f} bits\n\n")
        
        f.write(f"Low Risk Configurations (<10% attack success): {risk_info.get('low_risk_count', 0)}\n")
        f.write(f"  - Mean Layers: {risk_info.get('low_risk_mean_layers', 0):.2f}\n")
        f.write(f"  - Mean Entropy: {risk_info.get('low_risk_mean_entropy', 0):.2f} bits\n\n")
        
        # Correlations
        f.write("-"*80 + "\n")
        f.write("5. KEY CORRELATIONS\n")
        f.write("-"*80 + "\n\n")
        
        corr = stats_results.get('correlation', pd.DataFrame())
        if not corr.empty:
            f.write("Correlation with Security Score:\n")
            security_corr = corr['security_score'].sort_values(ascending=False)
            for var, corr_val in security_corr.items():
                if var != 'security_score':
                    f.write(f"  {var:25s}: {corr_val:7.3f}\n")
        
        f.write("\n")
        
        # Recommendations
        f.write("-"*80 + "\n")
        f.write("6. RECOMMENDATIONS\n")
        f.write("-"*80 + "\n\n")
        
        optimal_layers = model.data.groupby('n_layers')['security_score'].mean().idxmax()
        optimal_entropy = model.data.groupby('entropy_bits')['security_score'].mean().idxmax()
        optimal_puzzle = model.data.groupby('puzzle_entropy')['security_score'].mean().idxmax()
        
        f.write(f"✓ Optimal Layer Count: {optimal_layers} layers\n")
        f.write(f"✓ Optimal Entropy: {optimal_entropy} bits per layer\n")
        f.write(f"✓ Optimal Puzzle Entropy: {optimal_puzzle} bits\n")
        f.write(f"✓ Recommended Puzzle Window: ≤ 1.0 seconds\n")
        f.write(f"✓ Minimum Custodian Threshold: 3-of-5 for critical assets\n\n")
        
        f.write("-"*80 + "\n")
        f.write("END OF REPORT\n")
        f.write("-"*80 + "\n")
    
    logger.info(f"✓ Statistical report saved to {report_path}")

def main():
    """Main execution function"""
    print("="*80)
    print("CHAKRASEC ADVANCED STATISTICAL SECURITY ANALYSIS")
    print("="*80)
    print()
    
    start_time = time.time()
    
    # Initialize model
    model = AdvancedSecurityModel(n_samples=10000)
    
    # Generate data
    print("[1/6] Generating synthetic security data...")
    model.generate_synthetic_data()
    
    # Train ML model
    print("[2/6] Training machine learning model...")
    model.train_ml_model()
    
    # Statistical analysis
    print("[3/6] Performing statistical analysis...")
    stats_results = model.statistical_analysis()
    
    # Create visualizations
    print("[4/6] Creating advanced visualizations...")
    create_advanced_visualizations(model, stats_results)
    
    # Create interactive visualizations
    print("[5/6] Creating interactive Plotly visualizations...")
    create_interactive_plotly_visualizations(model)
    
    # Generate report
    print("[6/6] Generating statistical report...")
    generate_statistical_report(model, stats_results)
    
    elapsed_time = time.time() - start_time
    
    # Summary
    print()
    print("="*80)
    print("ANALYSIS COMPLETE!")
    print("="*80)
    print(f"Total execution time: {elapsed_time:.2f} seconds")
    print(f"Output directory: {OUTPUT_DIR}")
    print()
    print("Generated files:")
    print("  📊 Static Visualizations (PNG):")
    print("     - correlation_heatmap.png")
    print("     - security_3d_surface.png")
    print("     - distribution_analysis.png")
    print("     - regression_analysis.png")
    print("     - feature_importance.png")
    print("     - tradeoff_analysis.png")
    print()
    print("  🌐 Interactive Visualizations (HTML):")
    print("     - interactive_3d_security.html")
    print("     - interactive_dashboard.html")
    print("     - attack_simulation.html")
    print()
    print("  📄 Reports:")
    print("     - statistical_report.txt")
    print()
    print("="*80)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
