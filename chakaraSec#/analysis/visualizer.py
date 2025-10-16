"""
ChakraSec Analysis Visualization
Creates comprehensive graphs and plots for parameter analysis
"""

import matplotlib.pyplot as plt
import matplotlib.patches as patches
import seaborn as sns
import numpy as np
import pandas as pd
from typing import List, Dict, Any, Tuple, Optional
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import plotly.figure_factory as ff

from .parameters import ChakraSecConfig, ParameterSweep
from .simulator import AggregateResults

# Set style for matplotlib
plt.style.use('seaborn-v0_8')
sns.set_palette("husl")

class ChakraSecVisualizer:
    """Main visualization class for ChakraSec analysis"""
    
    def __init__(self, output_dir: str = "analysis/plots"):
        self.output_dir = output_dir
        import os
        os.makedirs(output_dir, exist_ok=True)
    
    def plot_security_vs_performance(self, 
                                   results: List[AggregateResults],
                                   configs: List[ChakraSecConfig],
                                   save_path: Optional[str] = None) -> go.Figure:
        """
        Plot security (P_success) vs performance (latency) tradeoff
        """
        # Extract data
        p_success = [r.probability_of_success for r in results]
        latency = [r.mean_total_latency for r in results]
        entropy_bits = [sum(c.security.entropy_per_layer) for c in configs]
        n_layers = [c.security.n_layers for c in configs]
        
        # Create scatter plot
        fig = go.Figure()
        
        # Add scatter points with color coding by entropy
        scatter = go.Scatter(
            x=latency,
            y=p_success,
            mode='markers+text',
            marker=dict(
                size=[n * 3 for n in n_layers],  # Size by number of layers
                color=entropy_bits,
                colorscale='Viridis',
                showscale=True,
                colorbar=dict(title="Total Entropy (bits)")
            ),
            text=[f"L{n}" for n in n_layers],
            textposition="top center",
            name="Configurations"
        )
        
        fig.add_trace(scatter)
        
        # Add Pareto frontier
        pareto_points = self._find_pareto_frontier(latency, p_success)
        if len(pareto_points) > 1:
            pareto_x, pareto_y = zip(*pareto_points)
            fig.add_trace(go.Scatter(
                x=pareto_x,
                y=pareto_y,
                mode='lines',
                line=dict(color='red', dash='dash'),
                name='Pareto Frontier'
            ))
        
        fig.update_layout(
            title="ChakraSec: Security vs Performance Tradeoff",
            xaxis_title="Mean Total Latency (seconds)",
            yaxis_title="Probability of Attack Success",
            width=800,
            height=600
        )
        
        if save_path:
            fig.write_html(f"{self.output_dir}/{save_path}")
        
        return fig
    
    def plot_entropy_analysis(self, 
                            results: List[AggregateResults],
                            configs: List[ChakraSecConfig],
                            save_path: Optional[str] = None) -> go.Figure:
        """
        Plot how entropy affects security across different parameters
        """
        # Create subplots
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=("Puzzle Entropy vs P_success", "Layer Entropy vs P_success",
                          "Entropy vs Time to Break", "Entropy Distribution"),
            specs=[[{"secondary_y": False}, {"secondary_y": False}],
                   [{"secondary_y": True}, {"secondary_y": False}]]
        )
        
        # Extract data
        puzzle_entropy = [c.puzzle.puzzle_entropy_bits for c in configs]
        total_entropy = [sum(c.security.entropy_per_layer) for c in configs]
        p_success = [r.probability_of_success for r in results]
        time_to_break = [r.mean_time_to_break if r.mean_time_to_break != float('inf') else 0 
                        for r in results]
        
        # Plot 1: Puzzle Entropy vs P_success
        fig.add_trace(
            go.Scatter(x=puzzle_entropy, y=p_success, mode='markers+lines',
                      name='Puzzle Entropy', marker=dict(color='blue')),
            row=1, col=1
        )
        
        # Plot 2: Total Entropy vs P_success
        fig.add_trace(
            go.Scatter(x=total_entropy, y=p_success, mode='markers+lines',
                      name='Total Entropy', marker=dict(color='green')),
            row=1, col=2
        )
        
        # Plot 3: Entropy vs Time to Break (dual axis)
        fig.add_trace(
            go.Scatter(x=total_entropy, y=p_success, mode='markers',
                      name='P_success', marker=dict(color='red')),
            row=2, col=1
        )
        
        fig.add_trace(
            go.Scatter(x=total_entropy, y=time_to_break, mode='markers',
                      name='Time to Break', marker=dict(color='orange'),
                      yaxis='y4'),
            row=2, col=1, secondary_y=True
        )
        
        # Plot 4: Entropy Distribution
        fig.add_trace(
            go.Histogram(x=total_entropy, name='Entropy Distribution',
                        marker=dict(color='purple')),
            row=2, col=2
        )
        
        fig.update_layout(
            title="ChakraSec: Entropy Analysis",
            width=1200,
            height=800
        )
        
        if save_path:
            fig.write_html(f"{self.output_dir}/{save_path}")
        
        return fig
    
    def plot_layer_analysis(self, 
                          results: List[AggregateResults],
                          configs: List[ChakraSecConfig],
                          save_path: Optional[str] = None) -> go.Figure:
        """
        Analyze the effect of number of layers
        """
        # Group results by number of layers
        layer_groups = {}
        for result, config in zip(results, configs):
            n_layers = config.security.n_layers
            if n_layers not in layer_groups:
                layer_groups[n_layers] = []
            layer_groups[n_layers].append(result)
        
        # Create box plots
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=("P_success by Layers", "Latency by Layers",
                          "Layers Broken Distribution", "Detection Rate by Layers")
        )
        
        layers_list = sorted(layer_groups.keys())
        
        # Plot 1: P_success by layers
        p_success_by_layer = [
            [r.probability_of_success for r in layer_groups[n]]
            for n in layers_list
        ]
        
        for i, n_layers in enumerate(layers_list):
            fig.add_trace(
                go.Box(y=p_success_by_layer[i], name=f"{n_layers} Layers",
                      showlegend=False),
                row=1, col=1
            )
        
        # Plot 2: Latency by layers
        latency_by_layer = [
            [r.mean_total_latency for r in layer_groups[n]]
            for n in layers_list
        ]
        
        for i, n_layers in enumerate(layers_list):
            fig.add_trace(
                go.Box(y=latency_by_layer[i], name=f"{n_layers} Layers",
                      showlegend=False),
                row=1, col=2
            )
        
        # Plot 3: Mean layers broken
        layers_broken = [
            np.mean([r.mean_layers_broken for r in layer_groups[n]])
            for n in layers_list
        ]
        
        fig.add_trace(
            go.Bar(x=layers_list, y=layers_broken, name='Mean Layers Broken',
                  marker=dict(color='orange')),
            row=2, col=1
        )
        
        # Plot 4: Detection rate
        detection_rates = [
            np.mean([r.detection_rate for r in layer_groups[n]])
            for n in layers_list
        ]
        
        fig.add_trace(
            go.Bar(x=layers_list, y=detection_rates, name='Detection Rate',
                  marker=dict(color='red')),
            row=2, col=2
        )
        
        fig.update_layout(
            title="ChakraSec: Layer Analysis",
            width=1200,
            height=800
        )
        
        if save_path:
            fig.write_html(f"{self.output_dir}/{save_path}")
        
        return fig
    
    def plot_puzzle_timing_analysis(self, 
                                  results: List[AggregateResults],
                                  configs: List[ChakraSecConfig],
                                  save_path: Optional[str] = None) -> go.Figure:
        """
        Analyze puzzle timing parameters (window and drift)
        """
        # Extract puzzle timing data
        data = []
        for result, config in zip(results, configs):
            data.append({
                'window': config.puzzle.puzzle_window,
                'drift': config.puzzle.puzzle_drift,
                'p_success': result.probability_of_success,
                'latency': result.mean_total_latency,
                'detection_rate': result.detection_rate
            })
        
        df = pd.DataFrame(data)
        
        # Create heatmaps
        fig = make_subplots(
            rows=1, cols=3,
            subplot_titles=("P_success Heatmap", "Latency Heatmap", "Detection Rate Heatmap")
        )
        
        # Pivot data for heatmaps
        windows = sorted(df['window'].unique())
        drifts = sorted(df['drift'].unique())
        
        # P_success heatmap
        p_success_matrix = df.pivot_table(
            values='p_success', index='drift', columns='window', fill_value=0
        )
        
        fig.add_trace(
            go.Heatmap(
                z=p_success_matrix.values,
                x=p_success_matrix.columns,
                y=p_success_matrix.index,
                colorscale='RdYlBu_r',
                name='P_success'
            ),
            row=1, col=1
        )
        
        # Latency heatmap
        latency_matrix = df.pivot_table(
            values='latency', index='drift', columns='window', fill_value=0
        )
        
        fig.add_trace(
            go.Heatmap(
                z=latency_matrix.values,
                x=latency_matrix.columns,
                y=latency_matrix.index,
                colorscale='Viridis',
                name='Latency'
            ),
            row=1, col=2
        )
        
        # Detection rate heatmap
        detection_matrix = df.pivot_table(
            values='detection_rate', index='drift', columns='window', fill_value=0
        )
        
        fig.add_trace(
            go.Heatmap(
                z=detection_matrix.values,
                x=detection_matrix.columns,
                y=detection_matrix.index,
                colorscale='Blues',
                name='Detection Rate'
            ),
            row=1, col=3
        )
        
        fig.update_layout(
            title="ChakraSec: Puzzle Timing Analysis",
            width=1500,
            height=500
        )
        
        if save_path:
            fig.write_html(f"{self.output_dir}/{save_path}")
        
        return fig
    
    def plot_threat_model_analysis(self, 
                                 results: List[AggregateResults],
                                 configs: List[ChakraSecConfig],
                                 save_path: Optional[str] = None) -> go.Figure:
        """
        Analyze different threat model parameters
        """
        # Extract threat model data
        attacker_speeds = [c.threat_model.attacker_attempts_per_second for c in configs]
        parallel_bots = [c.threat_model.attacker_parallel_bots for c in configs]
        p_success = [r.probability_of_success for r in results]
        time_to_break = [r.mean_time_to_break if r.mean_time_to_break != float('inf') else 0 
                        for r in results]
        
        # Create 3D scatter plot
        fig = go.Figure(data=[go.Scatter3d(
            x=np.log10(attacker_speeds),
            y=np.log10(parallel_bots),
            z=p_success,
            mode='markers',
            marker=dict(
                size=8,
                color=time_to_break,
                colorscale='Plasma',
                showscale=True,
                colorbar=dict(title="Time to Break (s)")
            ),
            text=[f"Speed: {s:.0f}/s<br>Bots: {b}<br>P_success: {p:.3f}" 
                  for s, b, p in zip(attacker_speeds, parallel_bots, p_success)],
            hovertemplate='%{text}<extra></extra>'
        )])
        
        fig.update_layout(
            title="ChakraSec: Threat Model Analysis",
            scene=dict(
                xaxis_title="Log10(Attacker Speed)",
                yaxis_title="Log10(Parallel Bots)",
                zaxis_title="Probability of Success"
            ),
            width=800,
            height=600
        )
        
        if save_path:
            fig.write_html(f"{self.output_dir}/{save_path}")
        
        return fig
    
    def plot_chakravyuh_visualization(self, 
                                    config: ChakraSecConfig,
                                    result: AggregateResults,
                                    save_path: Optional[str] = None) -> go.Figure:
        """
        Create a visual representation of the Chakravyuh (concentric layers)
        """
        fig = go.Figure()
        
        # Create concentric circles for each layer
        n_layers = config.security.n_layers
        colors = px.colors.qualitative.Set3[:n_layers]
        
        for i in range(n_layers):
            layer_id = n_layers - i  # Outer to inner
            radius = (i + 1) * 10
            
            # Calculate layer strength (inverse of break probability)
            entropy = config.security.entropy_per_layer[layer_id - 1]
            strength = min(1.0, entropy / 128.0)  # Normalize to 0-1
            
            # Create circle
            theta = np.linspace(0, 2*np.pi, 100)
            x = radius * np.cos(theta)
            y = radius * np.sin(theta)
            
            fig.add_trace(go.Scatter(
                x=x, y=y,
                mode='lines',
                fill='tonext' if i > 0 else 'toself',
                fillcolor=colors[i],
                line=dict(color=colors[i], width=3),
                name=f'Layer {layer_id} (E={entropy} bits)',
                opacity=0.3 + 0.4 * strength
            ))
            
            # Add layer label
            fig.add_annotation(
                x=radius * 0.7,
                y=radius * 0.7,
                text=f"L{layer_id}",
                showarrow=False,
                font=dict(size=12, color='black')
            )
        
        # Add center (protected asset)
        fig.add_trace(go.Scatter(
            x=[0], y=[0],
            mode='markers',
            marker=dict(size=20, color='gold', symbol='star'),
            name='Protected Asset'
        ))
        
        # Add attack success probability as title
        fig.update_layout(
            title=f"ChakraSec Chakravyuh Visualization<br>"
                  f"Attack Success Probability: {result.probability_of_success:.4f}",
            xaxis=dict(scaleanchor="y", scaleratio=1, showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            showlegend=True,
            width=600,
            height=600
        )
        
        if save_path:
            fig.write_html(f"{self.output_dir}/{save_path}")
        
        return fig
    
    def plot_parameter_sensitivity(self, 
                                 results: List[AggregateResults],
                                 configs: List[ChakraSecConfig],
                                 parameter_name: str,
                                 save_path: Optional[str] = None) -> go.Figure:
        """
        Plot sensitivity analysis for a specific parameter
        """
        # Extract parameter values
        param_values = []
        for config in configs:
            # Navigate nested parameter path
            parts = parameter_name.split('.')
            value = config
            for part in parts:
                value = getattr(value, part)
            param_values.append(value)
        
        # Create sensitivity plot
        fig = make_subplots(
            rows=2, cols=2,
            subplot_titles=(
                f"{parameter_name} vs P_success",
                f"{parameter_name} vs Latency",
                f"{parameter_name} vs Detection Rate",
                f"{parameter_name} vs Layers Broken"
            )
        )
        
        # Plot 1: Parameter vs P_success
        fig.add_trace(
            go.Scatter(
                x=param_values,
                y=[r.probability_of_success for r in results],
                mode='markers+lines',
                name='P_success',
                marker=dict(color='red')
            ),
            row=1, col=1
        )
        
        # Plot 2: Parameter vs Latency
        fig.add_trace(
            go.Scatter(
                x=param_values,
                y=[r.mean_total_latency for r in results],
                mode='markers+lines',
                name='Latency',
                marker=dict(color='blue')
            ),
            row=1, col=2
        )
        
        # Plot 3: Parameter vs Detection Rate
        fig.add_trace(
            go.Scatter(
                x=param_values,
                y=[r.detection_rate for r in results],
                mode='markers+lines',
                name='Detection Rate',
                marker=dict(color='green')
            ),
            row=2, col=1
        )
        
        # Plot 4: Parameter vs Layers Broken
        fig.add_trace(
            go.Scatter(
                x=param_values,
                y=[r.mean_layers_broken for r in results],
                mode='markers+lines',
                name='Layers Broken',
                marker=dict(color='orange')
            ),
            row=2, col=2
        )
        
        fig.update_layout(
            title=f"ChakraSec: Sensitivity Analysis - {parameter_name}",
            width=1200,
            height=800
        )
        
        if save_path:
            fig.write_html(f"{self.output_dir}/{save_path}")
        
        return fig
    
    def create_comprehensive_dashboard(self, 
                                     results: List[AggregateResults],
                                     configs: List[ChakraSecConfig],
                                     save_path: Optional[str] = None) -> go.Figure:
        """
        Create a comprehensive dashboard with all key metrics
        """
        # Create large subplot grid
        fig = make_subplots(
            rows=3, cols=3,
            subplot_titles=(
                "Security vs Performance", "Entropy Distribution", "Layer Analysis",
                "Threat Model Impact", "Detection Effectiveness", "Latency Breakdown",
                "Success Rate Trends", "Confidence Intervals", "System Overview"
            ),
            specs=[[{"secondary_y": False}, {"secondary_y": False}, {"secondary_y": False}],
                   [{"secondary_y": False}, {"secondary_y": False}, {"secondary_y": False}],
                   [{"secondary_y": False}, {"secondary_y": False}, {"secondary_y": False}]]
        )
        
        # Extract common data
        p_success = [r.probability_of_success for r in results]
        latency = [r.mean_total_latency for r in results]
        entropy = [sum(c.security.entropy_per_layer) for c in configs]
        n_layers = [c.security.n_layers for c in configs]
        
        # Plot 1: Security vs Performance
        fig.add_trace(
            go.Scatter(x=latency, y=p_success, mode='markers',
                      marker=dict(size=8, color='blue'),
                      name='Configs'),
            row=1, col=1
        )
        
        # Plot 2: Entropy Distribution
        fig.add_trace(
            go.Histogram(x=entropy, name='Entropy Dist',
                        marker=dict(color='green')),
            row=1, col=2
        )
        
        # Plot 3: Layer Analysis
        layer_counts = {}
        for n in n_layers:
            layer_counts[n] = layer_counts.get(n, 0) + 1
        
        fig.add_trace(
            go.Bar(x=list(layer_counts.keys()), y=list(layer_counts.values()),
                  name='Layer Counts', marker=dict(color='orange')),
            row=1, col=3
        )
        
        # Plot 4: Threat Model Impact
        attacker_speeds = [c.threat_model.attacker_attempts_per_second for c in configs]
        fig.add_trace(
            go.Scatter(x=np.log10(attacker_speeds), y=p_success,
                      mode='markers', name='Threat Impact',
                      marker=dict(color='red')),
            row=2, col=1
        )
        
        # Plot 5: Detection Effectiveness
        detection_rates = [r.detection_rate for r in results]
        fig.add_trace(
            go.Scatter(x=p_success, y=detection_rates,
                      mode='markers', name='Detection',
                      marker=dict(color='purple')),
            row=2, col=2
        )
        
        # Plot 6: Latency Breakdown
        fig.add_trace(
            go.Box(y=latency, name='Latency Distribution',
                  marker=dict(color='cyan')),
            row=2, col=3
        )
        
        # Plot 7: Success Rate Trends
        sorted_indices = np.argsort(entropy)
        sorted_p_success = [p_success[i] for i in sorted_indices]
        sorted_entropy = [entropy[i] for i in sorted_indices]
        
        fig.add_trace(
            go.Scatter(x=sorted_entropy, y=sorted_p_success,
                      mode='lines+markers', name='Success Trend',
                      marker=dict(color='magenta')),
            row=3, col=1
        )
        
        # Plot 8: Confidence Intervals
        ci_lower = [r.confidence_interval[0] for r in results]
        ci_upper = [r.confidence_interval[1] for r in results]
        
        fig.add_trace(
            go.Scatter(x=list(range(len(results))), y=p_success,
                      mode='markers', name='P_success',
                      error_y=dict(
                          type='data',
                          symmetric=False,
                          array=[u - p for u, p in zip(ci_upper, p_success)],
                          arrayminus=[p - l for l, p in zip(ci_lower, p_success)]
                      )),
            row=3, col=2
        )
        
        # Plot 9: System Overview (summary stats)
        summary_metrics = [
            np.mean(p_success),
            np.mean(latency),
            np.mean(detection_rates),
            np.mean([r.mean_layers_broken for r in results])
        ]
        summary_labels = ['Avg P_success', 'Avg Latency', 'Avg Detection', 'Avg Layers Broken']
        
        fig.add_trace(
            go.Bar(x=summary_labels, y=summary_metrics,
                  name='System Overview', marker=dict(color='gold')),
            row=3, col=3
        )
        
        fig.update_layout(
            title="ChakraSec: Comprehensive Analysis Dashboard",
            width=1800,
            height=1200,
            showlegend=False
        )
        
        if save_path:
            fig.write_html(f"{self.output_dir}/{save_path}")
        
        return fig
    
    def _find_pareto_frontier(self, x_values: List[float], y_values: List[float]) -> List[Tuple[float, float]]:
        """Find Pareto frontier points (minimize x, minimize y)"""
        points = list(zip(x_values, y_values))
        points.sort()
        
        pareto_points = []
        for point in points:
            if not pareto_points or point[1] < pareto_points[-1][1]:
                pareto_points.append(point)
        
        return pareto_points


