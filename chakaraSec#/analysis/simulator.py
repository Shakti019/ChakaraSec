"""
ChakraSec Monte Carlo Simulator
Simulates attack scenarios and measures security/performance metrics
"""

import numpy as np
import time
import random
from typing import Dict, List, Tuple, Any, Optional
from dataclasses import dataclass
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from .parameters import ChakraSecConfig, ActionOnFail, PuzzleType

@dataclass
class SimulationResult:
    """Results from a single simulation run"""
    success: bool
    time_to_break: Optional[float]  # seconds, None if not broken
    layers_broken: int
    total_attempts: int
    decoy_hits: int
    alerts_triggered: int
    total_latency: float
    detection_events: int
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "time_to_break": self.time_to_break,
            "layers_broken": self.layers_broken,
            "total_attempts": self.total_attempts,
            "decoy_hits": self.decoy_hits,
            "alerts_triggered": self.alerts_triggered,
            "total_latency": self.total_latency,
            "detection_events": self.detection_events
        }

@dataclass
class AggregateResults:
    """Aggregated results from multiple simulation runs"""
    config_id: str
    num_trials: int
    
    # Success metrics
    probability_of_success: float
    confidence_interval: Tuple[float, float]
    
    # Time metrics
    mean_time_to_break: float
    median_time_to_break: float
    time_to_break_95th: float
    
    # Performance metrics
    mean_total_latency: float
    mean_layers_broken: float
    
    # Security metrics
    total_decoy_hits: int
    total_alerts: int
    detection_rate: float
    
    # Statistical measures
    std_time_to_break: float
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "config_id": self.config_id,
            "num_trials": self.num_trials,
            "probability_of_success": self.probability_of_success,
            "confidence_interval": self.confidence_interval,
            "mean_time_to_break": self.mean_time_to_break,
            "median_time_to_break": self.median_time_to_break,
            "time_to_break_95th": self.time_to_break_95th,
            "mean_total_latency": self.mean_total_latency,
            "mean_layers_broken": self.mean_layers_broken,
            "total_decoy_hits": self.total_decoy_hits,
            "total_alerts": self.total_alerts,
            "detection_rate": self.detection_rate,
            "std_time_to_break": self.std_time_to_break
        }

class LayerSimulator:
    """Simulates individual layer security"""
    
    def __init__(self, config: ChakraSecConfig):
        self.config = config
        self.logger = logging.getLogger("LayerSimulator")
    
    def simulate_layer_attack(self, layer_id: int, attacker_capability: float) -> Tuple[bool, float, int]:
        """
        Simulate attack on a single layer
        
        Args:
            layer_id: Layer number (1-based)
            attacker_capability: Attacker's relative capability (0.0-1.0)
        
        Returns:
            (success, time_taken, attempts_made)
        """
        layer_idx = layer_id - 1
        
        # Handle case where layer_idx is out of range
        if layer_idx >= len(self.config.security.entropy_per_layer):
            entropy_bits = 32  # Default entropy
        else:
            entropy_bits = self.config.security.entropy_per_layer[layer_idx]
        
        # Calculate effective entropy considering attacker capability
        effective_entropy = entropy_bits * (1.0 - attacker_capability * 0.5)
        
        # For puzzle layers, add time-varying difficulty
        if layer_id == 5:  # Assuming layer 5 is the puzzle layer
            puzzle_difficulty = self._calculate_puzzle_difficulty()
            effective_entropy += puzzle_difficulty
        
        # Calculate expected attempts needed
        expected_attempts = 2 ** (effective_entropy - 1)  # Average case
        
        # Simulate attempts with exponential distribution
        attempts_made = max(1, int(np.random.exponential(expected_attempts)))
        
        # Calculate time based on attacker speed
        attempts_per_second = (
            self.config.threat_model.attacker_attempts_per_second * 
            self.config.threat_model.attacker_compute_factor
        )
        
        time_taken = attempts_made / attempts_per_second
        
        # Success probability based on attempts vs entropy
        success_prob = min(1.0, attempts_made / (2 ** effective_entropy))
        success = np.random.random() < success_prob
        
        return success, time_taken, attempts_made
    
    def _calculate_puzzle_difficulty(self) -> float:
        """Calculate additional difficulty from dynamic puzzles"""
        base_entropy = self.config.puzzle.puzzle_entropy_bits
        
        # Time-varying component
        window_factor = 1.0 / self.config.puzzle.puzzle_window
        drift_penalty = self.config.puzzle.puzzle_drift * 2  # bits lost to drift
        
        # Puzzle type difficulty multiplier
        type_multipliers = {
            PuzzleType.ROW_PARITY: 0.8,
            PuzzleType.LINEAR_TRANSFORM: 1.0,
            PuzzleType.HASH_CHALLENGE: 1.2
        }
        
        multiplier = type_multipliers.get(self.config.puzzle.puzzle_type, 1.0)
        
        effective_puzzle_entropy = (base_entropy - drift_penalty) * multiplier * window_factor
        return max(0, effective_puzzle_entropy)

class AttackSimulator:
    """Simulates complete attack scenarios"""
    
    def __init__(self, config: ChakraSecConfig):
        self.config = config
        self.layer_sim = LayerSimulator(config)
        self.logger = logging.getLogger("AttackSimulator")
    
    def simulate_single_attack(self, attacker_capability: float = 0.5) -> SimulationResult:
        """
        Simulate a single complete attack attempt
        
        Args:
            attacker_capability: Attacker's relative capability (0.0-1.0)
        
        Returns:
            SimulationResult with attack outcome
        """
        start_time = time.time()
        
        layers_broken = 0
        total_attempts = 0
        decoy_hits = 0
        alerts_triggered = 0
        detection_events = 0
        total_latency = 0.0
        
        # Attack layers from outside to inside (7 -> 1)
        for layer_id in range(self.config.security.n_layers, 0, -1):
            layer_idx = layer_id - 1
            
            # Simulate layer attack
            success, time_taken, attempts = self.layer_sim.simulate_layer_attack(
                layer_id, attacker_capability
            )
            
            total_attempts += attempts
            total_latency += time_taken
            
            # Check for detection
            detection_prob = (
                self.config.threat_model.detection_probability_per_attempt * 
                attempts
            )
            if np.random.random() < detection_prob:
                detection_events += 1
            
            if success:
                layers_broken += 1
                
                # Handle failure action
                # Check if the index is within bounds
                if layer_idx < len(self.config.policy.action_on_fail):
                    action = self.config.policy.action_on_fail[layer_idx]
                    
                    if action == ActionOnFail.RETURN_DECOY:
                        decoy_hits += 1
                        # Attacker might be fooled by decoy
                        if np.random.random() < self.config.policy.decoy_effectiveness:
                            # Attacker stops, thinking they succeeded
                            break
                    
                    elif action == ActionOnFail.ALERT:
                        alerts_triggered += 1
                    
                    elif action == ActionOnFail.DENY:
                        # Hard stop - attacker detected and blocked
                        break
                else:
                    # Default action if index is out of bounds
                    alerts_triggered += 1  # Default to alert
                
                # Continue to next layer
            else:
                # Failed to break this layer
                break
        
        # Determine overall success
        attack_success = layers_broken >= self.config.security.n_layers
        time_to_break = time.time() - start_time if attack_success else None
        
        return SimulationResult(
            success=attack_success,
            time_to_break=time_to_break,
            layers_broken=layers_broken,
            total_attempts=total_attempts,
            decoy_hits=decoy_hits,
            alerts_triggered=alerts_triggered,
            total_latency=total_latency,
            detection_events=detection_events
        )

class MonteCarloSimulator:
    """Monte Carlo simulation engine"""
    
    def __init__(self, config: ChakraSecConfig):
        self.config = config
        self.attack_sim = AttackSimulator(config)
        self.logger = logging.getLogger("MonteCarloSimulator")
    
    def run_simulation(self, 
                      num_trials: Optional[int] = None,
                      attacker_capability_range: Tuple[float, float] = (0.3, 0.8),
                      parallel: bool = True) -> AggregateResults:
        """
        Run Monte Carlo simulation
        
        Args:
            num_trials: Number of trials (uses config default if None)
            attacker_capability_range: Range of attacker capabilities to test
            parallel: Whether to run trials in parallel
        
        Returns:
            AggregateResults with statistical analysis
        """
        if num_trials is None:
            num_trials = self.config.experiment.sim_trials
        
        self.logger.info(f"Starting Monte Carlo simulation with {num_trials} trials")
        
        # Set random seed for reproducibility
        np.random.seed(self.config.experiment.random_seed)
        random.seed(self.config.experiment.random_seed)
        
        # Generate attacker capabilities for each trial
        attacker_capabilities = np.random.uniform(
            attacker_capability_range[0],
            attacker_capability_range[1],
            num_trials
        )
        
        # Run simulations
        if parallel and num_trials > 100:
            results = self._run_parallel_simulation(attacker_capabilities)
        else:
            results = self._run_sequential_simulation(attacker_capabilities)
        
        # Aggregate results
        return self._aggregate_results(results, f"config_{id(self.config)}")
    
    def _run_sequential_simulation(self, attacker_capabilities: np.ndarray) -> List[SimulationResult]:
        """Run simulations sequentially"""
        results = []
        
        for i, capability in enumerate(attacker_capabilities):
            if i % 1000 == 0:
                self.logger.info(f"Completed {i}/{len(attacker_capabilities)} trials")
            
            result = self.attack_sim.simulate_single_attack(capability)
            results.append(result)
        
        return results
    
    def _run_parallel_simulation(self, attacker_capabilities: np.ndarray) -> List[SimulationResult]:
        """Run simulations in parallel"""
        results = []
        
        with ThreadPoolExecutor(max_workers=4) as executor:
            # Submit all tasks
            futures = [
                executor.submit(self.attack_sim.simulate_single_attack, capability)
                for capability in attacker_capabilities
            ]
            
            # Collect results
            for i, future in enumerate(as_completed(futures)):
                if i % 1000 == 0:
                    self.logger.info(f"Completed {i}/{len(futures)} trials")
                
                result = future.result()
                results.append(result)
        
        return results
    
    def _aggregate_results(self, results: List[SimulationResult], config_id: str) -> AggregateResults:
        """Aggregate simulation results into statistics"""
        
        # Basic counts
        num_trials = len(results)
        successes = [r for r in results if r.success]
        num_successes = len(successes)
        
        # Success probability with confidence interval
        p_success = num_successes / num_trials
        ci = self._calculate_confidence_interval(p_success, num_trials)
        
        # Time to break statistics (only for successful attacks)
        if successes:
            times_to_break = [r.time_to_break for r in successes if r.time_to_break is not None]
            if times_to_break:
                mean_ttb = np.mean(times_to_break)
                median_ttb = np.median(times_to_break)
                ttb_95th = np.percentile(times_to_break, 95)
                std_ttb = np.std(times_to_break)
            else:
                mean_ttb = median_ttb = ttb_95th = std_ttb = 0.0
        else:
            mean_ttb = median_ttb = ttb_95th = std_ttb = float('inf')
        
        # Other metrics
        mean_latency = np.mean([r.total_latency for r in results])
        mean_layers_broken = np.mean([r.layers_broken for r in results])
        total_decoy_hits = sum(r.decoy_hits for r in results)
        total_alerts = sum(r.alerts_triggered for r in results)
        detection_rate = np.mean([r.detection_events > 0 for r in results])
        
        return AggregateResults(
            config_id=config_id,
            num_trials=num_trials,
            probability_of_success=p_success,
            confidence_interval=ci,
            mean_time_to_break=mean_ttb,
            median_time_to_break=median_ttb,
            time_to_break_95th=ttb_95th,
            mean_total_latency=mean_latency,
            mean_layers_broken=mean_layers_broken,
            total_decoy_hits=total_decoy_hits,
            total_alerts=total_alerts,
            detection_rate=detection_rate,
            std_time_to_break=std_ttb
        )
    
    def _calculate_confidence_interval(self, p: float, n: int, 
                                     confidence: float = 0.95) -> Tuple[float, float]:
        """Calculate confidence interval for success probability"""
        from scipy import stats
        
        # Use Wilson score interval for better small-sample performance
        z = stats.norm.ppf((1 + confidence) / 2)
        
        denominator = 1 + z**2 / n
        centre_adjusted_probability = p + z**2 / (2 * n)
        adjusted_standard_deviation = np.sqrt((p * (1 - p) + z**2 / (4 * n)) / n)
        
        lower_bound = (centre_adjusted_probability - z * adjusted_standard_deviation) / denominator
        upper_bound = (centre_adjusted_probability + z * adjusted_standard_deviation) / denominator
        
        return (max(0, lower_bound), min(1, upper_bound))

class ParameterSweepSimulator:
    """Runs simulations across parameter sweeps"""
    
    def __init__(self):
        self.logger = logging.getLogger("ParameterSweepSimulator")
    
    def run_parameter_sweep(self, 
                           configs: List[ChakraSecConfig],
                           trials_per_config: int = 1000) -> List[AggregateResults]:
        """
        Run simulations across multiple configurations
        
        Args:
            configs: List of configurations to test
            trials_per_config: Number of trials per configuration
        
        Returns:
            List of AggregateResults for each configuration
        """
        results = []
        
        for i, config in enumerate(configs):
            self.logger.info(f"Running simulation {i+1}/{len(configs)}")
            
            # Create simulator for this config
            simulator = MonteCarloSimulator(config)
            
            # Run simulation
            result = simulator.run_simulation(
                num_trials=trials_per_config,
                parallel=True
            )
            result.config_id = f"config_{i}"
            
            results.append(result)
        
        return results

class BenchmarkSimulator:
    """Benchmarks actual system performance"""
    
    def __init__(self, config: ChakraSecConfig):
        self.config = config
        self.logger = logging.getLogger("BenchmarkSimulator")
    
    def benchmark_layer_operations(self) -> Dict[str, float]:
        """Benchmark actual cryptographic operations"""
        import sys
        sys.path.append('..')
        
        try:
            from chakrasec import CryptoEngine, MatrixPuzzle
            
            crypto = CryptoEngine()
            puzzle = MatrixPuzzle(b"benchmark_secret")
            
            # Benchmark key generation
            start_time = time.time()
            for _ in range(100):
                crypto.generate_key()
            key_gen_time = (time.time() - start_time) / 100
            
            # Benchmark encryption
            key = crypto.generate_key()
            plaintext = b"benchmark_data" * 100  # 1.4KB
            aad = b"associated_data"
            
            start_time = time.time()
            for _ in range(100):
                crypto.encrypt_layer(key, plaintext, aad)
            encrypt_time = (time.time() - start_time) / 100
            
            # Benchmark decryption
            nonce, ciphertext = crypto.encrypt_layer(key, plaintext, aad)
            
            start_time = time.time()
            for _ in range(100):
                crypto.decrypt_layer(key, nonce, ciphertext, aad)
            decrypt_time = (time.time() - start_time) / 100
            
            # Benchmark puzzle generation
            client_seed = b"benchmark_client_seed"
            
            start_time = time.time()
            for _ in range(100):
                puzzle.generate_challenge(client_seed, 5, 64)
            puzzle_gen_time = (time.time() - start_time) / 100
            
            # Benchmark puzzle solving
            challenge = puzzle.generate_challenge(client_seed, 5, 64)
            session_nonce = b"benchmark_session_nonce_12345678"
            
            start_time = time.time()
            for _ in range(100):
                puzzle.create_proof(challenge, client_seed, session_nonce)
            puzzle_solve_time = (time.time() - start_time) / 100
            
            return {
                "key_generation": key_gen_time,
                "encryption": encrypt_time,
                "decryption": decrypt_time,
                "puzzle_generation": puzzle_gen_time,
                "puzzle_solving": puzzle_solve_time,
                "total_layer_time": encrypt_time + decrypt_time + puzzle_solve_time
            }
            
        except ImportError:
            self.logger.warning("ChakraSec modules not available for benchmarking")
            return {
                "key_generation": 0.001,
                "encryption": 0.002,
                "decryption": 0.002,
                "puzzle_generation": 0.005,
                "puzzle_solving": 0.010,
                "total_layer_time": 0.019
            }
    
    def update_config_with_benchmarks(self) -> ChakraSecConfig:
        """Update configuration with actual benchmark results"""
        benchmarks = self.benchmark_layer_operations()
        
        # Update performance parameters
        layer_time = benchmarks["total_layer_time"]
        self.config.performance.unwrap_latency_per_layer = [layer_time] * self.config.security.n_layers
        
        self.logger.info(f"Updated config with benchmark results: {layer_time:.4f}s per layer")
        
        return self.config
