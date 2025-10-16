"""
ChakraSec Analysis Runner
Main script to run comprehensive parameter analysis and generate reports
"""

import logging
import json
import time
from pathlib import Path
from typing import Dict, List, Any

from .parameters import (
    ChakraSecConfig, ParameterSweep, 
    BASELINE_CONFIG, HIGH_SECURITY_CONFIG, PERFORMANCE_CONFIG
)
from .simulator import (
    MonteCarloSimulator, ParameterSweepSimulator, 
    BenchmarkSimulator, AggregateResults
)
from .visualizer import ChakraSecVisualizer

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

class ChakraSecAnalysisRunner:
    """Main analysis runner for ChakraSec parameter testing"""
    
    def __init__(self, output_dir: str = "analysis/results"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.visualizer = ChakraSecVisualizer(str(self.output_dir / "plots"))
        self.logger = logging.getLogger("AnalysisRunner")
        
        # Results storage
        self.all_results: List[AggregateResults] = []
        self.all_configs: List[ChakraSecConfig] = []
    
    def run_baseline_analysis(self) -> Dict[str, AggregateResults]:
        """Run analysis on baseline configurations"""
        self.logger.info("Running baseline configuration analysis...")
        
        configs = {
            "baseline": BASELINE_CONFIG,
            "high_security": HIGH_SECURITY_CONFIG,
            "performance": PERFORMANCE_CONFIG
        }
        
        results = {}
        
        for name, config in configs.items():
            self.logger.info(f"Analyzing {name} configuration...")
            
            # Run benchmark to update performance parameters
            benchmark_sim = BenchmarkSimulator(config)
            config = benchmark_sim.update_config_with_benchmarks()
            
            # Run Monte Carlo simulation
            simulator = MonteCarloSimulator(config)
            result = simulator.run_simulation(num_trials=5000)
            result.config_id = name
            
            results[name] = result
            self.all_results.append(result)
            self.all_configs.append(config)
        
        # Save results
        self._save_results(results, "baseline_analysis.json")
        
        return results
    
    def run_entropy_sweep(self) -> Dict[str, List[AggregateResults]]:
        """Run entropy parameter sweep analysis"""
        self.logger.info("Running entropy sweep analysis...")
        
        base_config = BASELINE_CONFIG
        
        # Define entropy sweeps
        sweeps = {
            "puzzle_entropy": {
                "puzzle.puzzle_entropy_bits": [32, 64, 128, 256]
            },
            "layer_entropy": {
                "security.entropy_per_layer": [
                    [16] * 7, [32] * 7, [64] * 7, [128] * 7
                ]
            },
            "combined_entropy": {
                "puzzle.puzzle_entropy_bits": [64, 128],
                "security.entropy_per_layer": [[32] * 7, [64] * 7]
            }
        }
        
        results = {}
        
        for sweep_name, param_ranges in sweeps.items():
            self.logger.info(f"Running {sweep_name} sweep...")
            
            # Generate configurations
            configs = ParameterSweep.create_sweep_configs(base_config, param_ranges)
            
            # Run simulations
            sweep_simulator = ParameterSweepSimulator()
            sweep_results = sweep_simulator.run_parameter_sweep(configs, trials_per_config=2000)
            
            results[sweep_name] = sweep_results
            self.all_results.extend(sweep_results)
            self.all_configs.extend(configs)
        
        # Save results
        self._save_sweep_results(results, "entropy_sweep.json")
        
        return results
    
    def run_layer_analysis(self) -> Dict[str, List[AggregateResults]]:
        """Run layer count analysis"""
        self.logger.info("Running layer analysis...")
        
        base_config = BASELINE_CONFIG
        
        # Layer count sweep
        param_ranges = {
            "security.n_layers": [3, 5, 7, 9],
            "security.entropy_per_layer": [
                [32] * 3, [32] * 5, [32] * 7, [32] * 9
            ],
            "performance.unwrap_latency_per_layer": [
                [0.2] * 3, [0.2] * 5, [0.2] * 7, [0.2] * 9
            ]
        }
        
        configs = ParameterSweep.create_sweep_configs(base_config, param_ranges)
        
        # Run simulations
        sweep_simulator = ParameterSweepSimulator()
        results = sweep_simulator.run_parameter_sweep(configs, trials_per_config=2000)
        
        self.all_results.extend(results)
        self.all_configs.extend(configs)
        
        # Save results
        self._save_results({"layer_analysis": results}, "layer_analysis.json")
        
        return {"layer_analysis": results}
    
    def run_puzzle_timing_analysis(self) -> Dict[str, List[AggregateResults]]:
        """Run puzzle timing parameter analysis"""
        self.logger.info("Running puzzle timing analysis...")
        
        base_config = BASELINE_CONFIG
        
        # Puzzle timing sweep
        param_ranges = {
            "puzzle.puzzle_window": [0.5, 1.0, 2.0, 5.0],
            "puzzle.puzzle_drift": [0, 1, 2, 3]
        }
        
        configs = ParameterSweep.create_sweep_configs(base_config, param_ranges)
        
        # Run simulations
        sweep_simulator = ParameterSweepSimulator()
        results = sweep_simulator.run_parameter_sweep(configs, trials_per_config=1500)
        
        self.all_results.extend(results)
        self.all_configs.extend(configs)
        
        # Save results
        self._save_results({"puzzle_timing": results}, "puzzle_timing.json")
        
        return {"puzzle_timing": results}
    
    def run_threat_model_analysis(self) -> Dict[str, List[AggregateResults]]:
        """Run threat model parameter analysis"""
        self.logger.info("Running threat model analysis...")
        
        base_config = BASELINE_CONFIG
        
        # Threat model sweep
        param_ranges = {
            "threat_model.attacker_attempts_per_second": [10, 100, 1000, 10000],
            "threat_model.attacker_parallel_bots": [1, 10, 100, 1000]
        }
        
        configs = ParameterSweep.create_sweep_configs(base_config, param_ranges)
        
        # Run simulations
        sweep_simulator = ParameterSweepSimulator()
        results = sweep_simulator.run_parameter_sweep(configs, trials_per_config=1500)
        
        self.all_results.extend(results)
        self.all_configs.extend(configs)
        
        # Save results
        self._save_results({"threat_model": results}, "threat_model.json")
        
        return {"threat_model": results}
    
    def run_performance_vs_security_analysis(self) -> Dict[str, List[AggregateResults]]:
        """Run comprehensive performance vs security tradeoff analysis"""
        self.logger.info("Running performance vs security analysis...")
        
        base_config = BASELINE_CONFIG
        
        # Combined parameter sweep
        param_ranges = {
            "security.n_layers": [3, 5, 7, 9],
            "puzzle.puzzle_entropy_bits": [32, 64, 128, 256],
            "security.entropy_per_layer": [
                [16] * 3 + [0] * 6,  # Pad with zeros for unused layers
                [32] * 5 + [0] * 4,
                [32] * 7,
                [64] * 9
            ][:4]  # Match the number of layer configurations
        }
        
        # Manually create configs to ensure proper layer alignment
        configs = []
        layer_counts = [3, 5, 7, 9]
        entropy_levels = [32, 64, 128, 256]
        
        for n_layers in layer_counts:
            for puzzle_entropy in entropy_levels:
                for base_entropy in [16, 32, 64]:
                    config = ChakraSecConfig()
                    config.security.n_layers = n_layers
                    config.puzzle.puzzle_entropy_bits = puzzle_entropy
                    config.security.entropy_per_layer = [base_entropy] * n_layers
                    config.performance.unwrap_latency_per_layer = [0.2] * n_layers
                    
                    configs.append(config)
        
        # Run simulations
        sweep_simulator = ParameterSweepSimulator()
        results = sweep_simulator.run_parameter_sweep(configs, trials_per_config=1000)
        
        self.all_results.extend(results)
        self.all_configs.extend(configs)
        
        # Save results
        self._save_results({"performance_vs_security": results}, "performance_vs_security.json")
        
        return {"performance_vs_security": results}
    
    def generate_visualizations(self):
        """Generate all visualization plots"""
        self.logger.info("Generating visualizations...")
        
        if not self.all_results or not self.all_configs:
            self.logger.warning("No results available for visualization")
            return
        
        # Security vs Performance plot
        self.visualizer.plot_security_vs_performance(
            self.all_results, self.all_configs, "security_vs_performance.html"
        )
        
        # Entropy analysis
        self.visualizer.plot_entropy_analysis(
            self.all_results, self.all_configs, "entropy_analysis.html"
        )
        
        # Layer analysis
        self.visualizer.plot_layer_analysis(
            self.all_results, self.all_configs, "layer_analysis.html"
        )
        
        # Puzzle timing analysis
        self.visualizer.plot_puzzle_timing_analysis(
            self.all_results, self.all_configs, "puzzle_timing.html"
        )
        
        # Threat model analysis
        self.visualizer.plot_threat_model_analysis(
            self.all_results, self.all_configs, "threat_model.html"
        )
        
        # Chakravyuh visualization for baseline
        if self.all_results:
            self.visualizer.plot_chakravyuh_visualization(
                self.all_configs[0], self.all_results[0], "chakravyuh_visualization.html"
            )
        
        # Comprehensive dashboard
        self.visualizer.create_comprehensive_dashboard(
            self.all_results, self.all_configs, "comprehensive_dashboard.html"
        )
        
        # Parameter sensitivity analyses
        sensitive_params = [
            "puzzle.puzzle_entropy_bits",
            "security.n_layers",
            "threat_model.attacker_attempts_per_second"
        ]
        
        for param in sensitive_params:
            try:
                self.visualizer.plot_parameter_sensitivity(
                    self.all_results, self.all_configs, param, 
                    f"sensitivity_{param.replace('.', '_')}.html"
                )
            except Exception as e:
                self.logger.warning(f"Could not generate sensitivity plot for {param}: {e}")
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive analysis report"""
        self.logger.info("Generating analysis report...")
        
        if not self.all_results:
            return {"error": "No results available"}
        
        # Calculate summary statistics
        p_success_values = [r.probability_of_success for r in self.all_results]
        latency_values = [r.mean_total_latency for r in self.all_results]
        
        report = {
            "summary": {
                "total_configurations": len(self.all_configs),
                "total_simulations": sum(r.num_trials for r in self.all_results),
                "analysis_timestamp": time.time(),
                "mean_p_success": float(np.mean(p_success_values)),
                "std_p_success": float(np.std(p_success_values)),
                "mean_latency": float(np.mean(latency_values)),
                "std_latency": float(np.std(latency_values))
            },
            "best_configurations": self._find_best_configurations(),
            "parameter_insights": self._generate_parameter_insights(),
            "recommendations": self._generate_recommendations()
        }
        
        # Save report
        with open(self.output_dir / "analysis_report.json", 'w') as f:
            json.dump(report, f, indent=2)
        
        return report
    
    def run_complete_analysis(self) -> Dict[str, Any]:
        """Run complete parameter analysis suite"""
        self.logger.info("Starting complete ChakraSec parameter analysis...")
        
        start_time = time.time()
        
        try:
            # Run all analyses
            baseline_results = self.run_baseline_analysis()
            entropy_results = self.run_entropy_sweep()
            layer_results = self.run_layer_analysis()
            puzzle_results = self.run_puzzle_timing_analysis()
            threat_results = self.run_threat_model_analysis()
            perf_sec_results = self.run_performance_vs_security_analysis()
            
            # Generate visualizations
            self.generate_visualizations()
            
            # Generate report
            report = self.generate_report()
            
            total_time = time.time() - start_time
            
            self.logger.info(f"Complete analysis finished in {total_time:.2f} seconds")
            self.logger.info(f"Results saved to: {self.output_dir}")
            
            return {
                "success": True,
                "total_time": total_time,
                "output_directory": str(self.output_dir),
                "summary": report["summary"]
            }
            
        except Exception as e:
            self.logger.error(f"Analysis failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "total_time": time.time() - start_time
            }
    
    def _save_results(self, results: Dict[str, Any], filename: str):
        """Save results to JSON file"""
        # Convert results to serializable format
        serializable_results = {}
        for key, value in results.items():
            if isinstance(value, list):
                serializable_results[key] = [r.to_dict() for r in value]
            else:
                serializable_results[key] = value.to_dict()
        
        with open(self.output_dir / filename, 'w') as f:
            json.dump(serializable_results, f, indent=2)
    
    def _save_sweep_results(self, results: Dict[str, List[AggregateResults]], filename: str):
        """Save sweep results to JSON file"""
        serializable_results = {}
        for sweep_name, sweep_results in results.items():
            serializable_results[sweep_name] = [r.to_dict() for r in sweep_results]
        
        with open(self.output_dir / filename, 'w') as f:
            json.dump(serializable_results, f, indent=2)
    
    def _find_best_configurations(self) -> Dict[str, Any]:
        """Find best configurations based on different criteria"""
        if not self.all_results:
            return {}
        
        # Find configurations optimizing different objectives
        best_security_idx = min(range(len(self.all_results)), 
                               key=lambda i: self.all_results[i].probability_of_success)
        
        best_performance_idx = min(range(len(self.all_results)), 
                                  key=lambda i: self.all_results[i].mean_total_latency)
        
        # Find balanced configuration (minimize weighted sum)
        balanced_scores = [
            0.7 * r.probability_of_success + 0.3 * (r.mean_total_latency / 10.0)
            for r in self.all_results
        ]
        best_balanced_idx = min(range(len(balanced_scores)), key=lambda i: balanced_scores[i])
        
        return {
            "best_security": {
                "config_id": self.all_results[best_security_idx].config_id,
                "p_success": self.all_results[best_security_idx].probability_of_success,
                "latency": self.all_results[best_security_idx].mean_total_latency
            },
            "best_performance": {
                "config_id": self.all_results[best_performance_idx].config_id,
                "p_success": self.all_results[best_performance_idx].probability_of_success,
                "latency": self.all_results[best_performance_idx].mean_total_latency
            },
            "best_balanced": {
                "config_id": self.all_results[best_balanced_idx].config_id,
                "p_success": self.all_results[best_balanced_idx].probability_of_success,
                "latency": self.all_results[best_balanced_idx].mean_total_latency,
                "balanced_score": balanced_scores[best_balanced_idx]
            }
        }
    
    def _generate_parameter_insights(self) -> Dict[str, Any]:
        """Generate insights about parameter effects"""
        import numpy as np
        
        insights = {}
        
        # Analyze entropy effects
        entropy_values = [sum(c.security.entropy_per_layer) for c in self.all_configs]
        p_success_values = [r.probability_of_success for r in self.all_results]
        
        if len(set(entropy_values)) > 1:
            correlation = np.corrcoef(entropy_values, p_success_values)[0, 1]
            insights["entropy_correlation"] = {
                "correlation": float(correlation),
                "interpretation": "Strong negative correlation" if correlation < -0.7 
                               else "Moderate negative correlation" if correlation < -0.3
                               else "Weak correlation"
            }
        
        # Analyze layer count effects
        layer_counts = [c.security.n_layers for c in self.all_configs]
        if len(set(layer_counts)) > 1:
            layer_correlation = np.corrcoef(layer_counts, p_success_values)[0, 1]
            insights["layer_correlation"] = {
                "correlation": float(layer_correlation),
                "interpretation": "More layers generally improve security" if layer_correlation < -0.3
                               else "Layer count has minimal security impact"
            }
        
        return insights
    
    def _generate_recommendations(self) -> List[str]:
        """Generate configuration recommendations based on analysis"""
        recommendations = []
        
        if not self.all_results:
            return ["No analysis results available for recommendations"]
        
        # Analyze results to generate recommendations
        p_success_values = [r.probability_of_success for r in self.all_results]
        latency_values = [r.mean_total_latency for r in self.all_results]
        
        mean_p_success = np.mean(p_success_values)
        mean_latency = np.mean(latency_values)
        
        if mean_p_success > 0.1:
            recommendations.append(
                "Consider increasing entropy per layer or total number of layers to improve security"
            )
        
        if mean_latency > 5.0:
            recommendations.append(
                "Consider reducing number of layers or optimizing cryptographic operations for better performance"
            )
        
        # Analyze puzzle parameters
        puzzle_entropies = [c.puzzle.puzzle_entropy_bits for c in self.all_configs]
        if max(puzzle_entropies) - min(puzzle_entropies) > 0:
            high_entropy_results = [
                r.probability_of_success for r, c in zip(self.all_results, self.all_configs)
                if c.puzzle.puzzle_entropy_bits >= 128
            ]
            if high_entropy_results and np.mean(high_entropy_results) < mean_p_success:
                recommendations.append(
                    "Higher puzzle entropy (≥128 bits) significantly improves security"
                )
        
        recommendations.append(
            "Use 7-layer configuration with 64+ bit puzzle entropy for balanced security/performance"
        )
        
        recommendations.append(
            "Implement dynamic puzzle windows ≤1 second for maximum moving-target effectiveness"
        )
        
        return recommendations

def main():
    """Main entry point for analysis"""
    runner = ChakraSecAnalysisRunner()
    result = runner.run_complete_analysis()
    
    if result["success"]:
        print(f"\n✅ ChakraSec Analysis Complete!")
        print(f"📊 Total Time: {result['total_time']:.2f} seconds")
        print(f"📁 Results: {result['output_directory']}")
        print(f"🔍 Configurations Tested: {result['summary']['total_configurations']}")
        print(f"🎯 Total Simulations: {result['summary']['total_simulations']}")
        print(f"🔒 Mean P_success: {result['summary']['mean_p_success']:.6f}")
        print(f"⚡ Mean Latency: {result['summary']['mean_latency']:.3f}s")
    else:
        print(f"\n❌ Analysis Failed: {result['error']}")

if __name__ == "__main__":
    main()


