"""
ChakraSec Parameter Definitions and Configuration
Comprehensive parameter system for security/performance analysis
"""

from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Union
from enum import Enum
import numpy as np

class PuzzleType(Enum):
    """Types of cryptographic puzzles"""
    ROW_PARITY = "row_parity"
    LINEAR_TRANSFORM = "linear_transform"
    HASH_CHALLENGE = "hash_challenge"

class HashAlgorithm(Enum):
    """Hash algorithms for commitments"""
    SHA256 = "sha256"
    SHA384 = "sha384"
    SHA512 = "sha512"
    BLAKE2B = "blake2b"

class SignatureAlgorithm(Enum):
    """Signature algorithms"""
    ED25519 = "ed25519"
    ECDSA_P256 = "ecdsa_p256"
    RSA_PSS = "rsa_pss"

class WrapAlgorithm(Enum):
    """Key wrapping algorithms"""
    RSA_OAEP = "rsa_oaep"
    AES_KW = "aes_kw"
    CHACHA20_POLY1305 = "chacha20_poly1305"

class SecretSharingScheme(Enum):
    """Secret sharing schemes"""
    SHAMIR = "shamir"
    FELDMAN_VSS = "feldman_vss"
    PEDERSEN_VSS = "pedersen_vss"

class ActionOnFail(Enum):
    """Actions to take on policy failure"""
    RETURN_DECOY = "return_decoy"
    ALERT = "alert"
    DENY = "deny"
    LOG = "log"

@dataclass
class SecurityParameters:
    """Core security and cryptographic parameters"""
    
    # Layer configuration
    n_layers: int = 7  # Range: 1..9
    key_size_bytes: int = 32  # Range: 16, 24, 32 (AES-128, 192, 256)
    entropy_per_layer: List[int] = field(default_factory=lambda: [32] * 7)  # bits per layer
    
    # Cryptographic algorithms
    commitment_hash_alg: HashAlgorithm = HashAlgorithm.SHA256
    signature_alg: SignatureAlgorithm = SignatureAlgorithm.ED25519
    wrap_algorithm: WrapAlgorithm = WrapAlgorithm.RSA_OAEP
    secret_sharing_scheme: SecretSharingScheme = SecretSharingScheme.SHAMIR
    
    # KDF parameters
    kdf_info: bytes = b"chakrasec-kdf"
    salt_length: int = 16

@dataclass
class PuzzleParameters:
    """Dynamic puzzle and moving-target parameters"""
    
    puzzle_type: PuzzleType = PuzzleType.LINEAR_TRANSFORM
    puzzle_entropy_bits: int = 64  # Range: 8..256
    puzzle_window: float = 1.0  # seconds, Range: 0.5..10
    puzzle_drift: int = 1  # windows, Range: 0..3
    
    # Algorithm-specific parameters
    matrix_size: int = 8
    puzzle_seed_binding: bool = True
    puzzle_mac_kdf_len: int = 32
    
    # HKDF parameters for puzzle generation
    hkdf_info: bytes = b"matrix-expand"

@dataclass
class PolicyParameters:
    """Policy and layer-specific parameters"""
    
    # Custodian configuration
    custodian_threshold: int = 3  # Range: 1..n
    number_of_custodians: int = 5  # Range: 3..7
    
    # Policy strictness (0.0 = minimal, 1.0 = maximum)
    policy_strictness_profile: float = 0.7  # Range: 0..1
    
    # Per-layer actions on failure
    action_on_fail: List[ActionOnFail] = field(default_factory=lambda: [
        ActionOnFail.ALERT,      # Layer 7 (outermost)
        ActionOnFail.RETURN_DECOY,  # Layer 6
        ActionOnFail.RETURN_DECOY,  # Layer 5
        ActionOnFail.ALERT,      # Layer 4
        ActionOnFail.DENY,       # Layer 3
        ActionOnFail.DENY,       # Layer 2
        ActionOnFail.DENY        # Layer 1 (innermost)
    ])
    
    # Deception effectiveness
    decoy_effectiveness: float = 0.3  # Range: 0..1

@dataclass
class RuntimeParameters:
    """Runtime and protocol parameters"""
    
    # Session management
    session_nonce_length: int = 16  # bytes
    release_token_ttl: int = 30  # seconds, Range: 1..300
    token_signature_alg: SignatureAlgorithm = SignatureAlgorithm.ED25519
    single_use_token: bool = True
    
    # Security policies
    key_zeroize_policy: str = "immediate"
    
    # Timeouts
    ge_verification_timeout: float = 2.0  # seconds, Range: 0.5..10
    custodian_response_timeout: float = 30.0  # seconds, Range: 10..60

@dataclass
class PerformanceParameters:
    """Performance and UX parameters"""
    
    # Latency measurements (will be populated by benchmarks)
    unwrap_latency_per_layer: List[float] = field(default_factory=lambda: [0.2] * 7)  # seconds
    user_proof_time: float = 1.0  # seconds, Range: 0.05..2.0
    
    # Error rates
    false_negative_rate: float = 0.05  # Range: 0..0.2
    false_positive_rate: float = 0.001  # Range: 0..0.01
    
    # Network parameters
    network_rtt_ms: float = 50.0  # milliseconds, Range: 10..500
    
    # Caching
    cache_ttl_keys: int = 30  # seconds, Range: 0..300
    max_concurrent_unwraps: int = 100
    
    @property
    def total_unwrap_latency(self) -> float:
        """Total latency for all layers"""
        return sum(self.unwrap_latency_per_layer)

@dataclass
class ThreatModelParameters:
    """Attacker and threat model parameters"""
    
    # Attacker capabilities
    attacker_attempts_per_second: float = 100.0  # Range: 1..1e6
    attacker_parallel_bots: int = 10  # Range: 1..1e4
    attacker_compute_factor: float = 1.0  # GPU/ASIC speedup multiplier
    
    # Detection
    detection_probability_per_attempt: float = 0.1  # Range: 0..1
    
    # Rate limiting
    retry_backoff_base: float = 1.0  # seconds
    retry_backoff_multiplier: float = 2.0
    max_retry_attempts: int = 5

@dataclass
class OperationalParameters:
    """Operational and availability parameters"""
    
    # Audit and logging
    audit_log_replication_factor: int = 3
    audit_event_retention_days: int = 365
    
    # HSM parameters
    hsm_unseal_latency: float = 0.1  # seconds, Range: 0.05..0.5
    
    # Availability
    custodian_availability_prob: float = 0.95  # Range: 0..1
    
    # Cost (placeholder for economic analysis)
    operational_cost_per_unwrap: float = 0.001  # currency units
    provisioning_latency: float = 5.0  # seconds

@dataclass
class ExperimentParameters:
    """Parameters for measurement and experiments"""
    
    # Simulation parameters
    sim_trials: int = 10000
    time_horizon_seconds: int = 3600  # 1 hour
    bootstrap_samples: int = 1000
    confidence_level: float = 0.95
    random_seed: int = 42
    
    # Metrics to collect
    metrics_collected: List[str] = field(default_factory=lambda: [
        "p_success", "mttb", "total_latency", "decoy_hits", 
        "fnr", "fpr", "cpu_usage", "memory_usage"
    ])

@dataclass
class MonitoringParameters:
    """Monitoring and logging parameters"""
    
    # Logging
    log_signature_alg: SignatureAlgorithm = SignatureAlgorithm.ED25519
    
    # Alert thresholds
    alert_thresholds: Dict[str, float] = field(default_factory=lambda: {
        "failed_attempts_per_minute": 10.0,
        "decoy_rate_threshold": 0.1,
        "custodian_failure_rate": 0.2,
        "average_latency_threshold": 5.0
    })

@dataclass
class UXParameters:
    """User experience tuning parameters"""
    
    # Clock synchronization
    allowed_clock_skew_seconds: int = 2
    
    # User interaction
    user_retry_window: int = 60  # seconds
    grace_attempts: int = 2
    human_approval_timeout: int = 300  # seconds

@dataclass
class ChakraSecConfig:
    """Complete ChakraSec configuration"""
    
    security: SecurityParameters = field(default_factory=SecurityParameters)
    puzzle: PuzzleParameters = field(default_factory=PuzzleParameters)
    policy: PolicyParameters = field(default_factory=PolicyParameters)
    runtime: RuntimeParameters = field(default_factory=RuntimeParameters)
    performance: PerformanceParameters = field(default_factory=PerformanceParameters)
    threat_model: ThreatModelParameters = field(default_factory=ThreatModelParameters)
    operational: OperationalParameters = field(default_factory=OperationalParameters)
    experiment: ExperimentParameters = field(default_factory=ExperimentParameters)
    monitoring: MonitoringParameters = field(default_factory=MonitoringParameters)
    ux: UXParameters = field(default_factory=UXParameters)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary"""
        result = {}
        for field_name, field_value in self.__dict__.items():
            if hasattr(field_value, '__dict__'):
                result[field_name] = {}
                for sub_field, sub_value in field_value.__dict__.items():
                    if isinstance(sub_value, Enum):
                        result[field_name][sub_field] = sub_value.value
                    elif isinstance(sub_value, bytes):
                        result[field_name][sub_field] = sub_value.hex()
                    else:
                        result[field_name][sub_field] = sub_value
            else:
                result[field_name] = field_value
        return result
    
    @classmethod
    def get_baseline_config(cls) -> 'ChakraSecConfig':
        """Get recommended baseline configuration for experiments"""
        config = cls()
        
        # Security parameters
        config.security.n_layers = 7
        config.security.key_size_bytes = 32
        config.security.entropy_per_layer = [32, 32, 64, 32, 32, 32, 32]  # Layer 5 has puzzle
        
        # Puzzle parameters
        config.puzzle.puzzle_entropy_bits = 64
        config.puzzle.puzzle_window = 1.0
        config.puzzle.puzzle_drift = 1
        
        # Threat model
        config.threat_model.attacker_attempts_per_second = 100.0
        config.threat_model.attacker_parallel_bots = 10
        
        # Performance estimates
        config.performance.unwrap_latency_per_layer = [0.2] * 7  # 0.2s per layer
        config.performance.cache_ttl_keys = 30
        
        # Experiment parameters
        config.experiment.sim_trials = 10000
        
        return config
    
    @classmethod
    def get_high_security_config(cls) -> 'ChakraSecConfig':
        """Get high-security configuration"""
        config = cls.get_baseline_config()
        
        # Increase security parameters
        config.security.entropy_per_layer = [64, 64, 128, 64, 64, 64, 64]
        config.puzzle.puzzle_entropy_bits = 128
        config.puzzle.puzzle_window = 0.5  # Faster changing puzzles
        
        # Stricter policies
        config.policy.policy_strictness_profile = 0.9
        config.policy.custodian_threshold = 4
        config.policy.number_of_custodians = 7
        
        # More conservative threat model
        config.threat_model.attacker_attempts_per_second = 1000.0
        config.threat_model.attacker_parallel_bots = 100
        
        return config
    
    @classmethod
    def get_performance_config(cls) -> 'ChakraSecConfig':
        """Get performance-optimized configuration"""
        config = cls.get_baseline_config()
        
        # Reduce layers for faster processing
        config.security.n_layers = 5
        config.security.entropy_per_layer = [32, 32, 64, 32, 32]
        
        # Faster puzzles
        config.puzzle.puzzle_entropy_bits = 32
        config.puzzle.puzzle_window = 2.0  # Slower changing
        
        # Relaxed policies
        config.policy.policy_strictness_profile = 0.5
        config.policy.custodian_threshold = 2
        config.policy.number_of_custodians = 3
        
        # Optimistic performance
        config.performance.unwrap_latency_per_layer = [0.1] * 5
        config.performance.cache_ttl_keys = 60
        
        return config

class ParameterSweep:
    """Utility class for parameter sweeping in experiments"""
    
    @staticmethod
    def create_sweep_configs(base_config: ChakraSecConfig, 
                           parameter_ranges: Dict[str, List[Any]]) -> List[ChakraSecConfig]:
        """
        Create multiple configurations by sweeping parameters
        
        Args:
            base_config: Base configuration to modify
            parameter_ranges: Dict mapping parameter paths to value lists
                Example: {
                    "puzzle.puzzle_entropy_bits": [32, 64, 128],
                    "security.n_layers": [5, 7, 9]
                }
        
        Returns:
            List of configurations with all parameter combinations
        """
        import itertools
        
        # Get all parameter combinations
        param_names = list(parameter_ranges.keys())
        param_values = list(parameter_ranges.values())
        combinations = list(itertools.product(*param_values))
        
        configs = []
        for combination in combinations:
            # Create a copy of base config
            import copy
            config = copy.deepcopy(base_config)
            
            # Apply parameter values
            for param_name, value in zip(param_names, combination):
                ParameterSweep._set_nested_param(config, param_name, value)
            
            configs.append(config)
        
        return configs
    
    @staticmethod
    def _set_nested_param(obj: Any, param_path: str, value: Any):
        """Set a nested parameter using dot notation"""
        parts = param_path.split('.')
        current = obj
        
        # Navigate to the parent object
        for part in parts[:-1]:
            current = getattr(current, part)
        
        # Set the final parameter
        setattr(current, parts[-1], value)
    
    @staticmethod
    def get_common_sweeps() -> Dict[str, Dict[str, List[Any]]]:
        """Get common parameter sweeps for analysis"""
        return {
            "entropy_analysis": {
                "puzzle.puzzle_entropy_bits": [32, 64, 128, 256],
                "security.entropy_per_layer": [
                    [16] * 7, [32] * 7, [64] * 7, [128] * 7
                ]
            },
            
            "layer_analysis": {
                "security.n_layers": [3, 5, 7, 9],
                "performance.unwrap_latency_per_layer": [
                    [0.1] * 3, [0.1] * 5, [0.1] * 7, [0.1] * 9
                ]
            },
            
            "puzzle_timing": {
                "puzzle.puzzle_window": [0.5, 1.0, 2.0, 5.0],
                "puzzle.puzzle_drift": [0, 1, 2, 3]
            },
            
            "threat_model": {
                "threat_model.attacker_attempts_per_second": [10, 100, 1000, 10000],
                "threat_model.attacker_parallel_bots": [1, 10, 100, 1000]
            },
            
            "performance_vs_security": {
                "security.n_layers": [3, 5, 7, 9],
                "puzzle.puzzle_entropy_bits": [32, 64, 128, 256]
            }
        }

# Pre-defined configurations for common scenarios
BASELINE_CONFIG = ChakraSecConfig.get_baseline_config()
HIGH_SECURITY_CONFIG = ChakraSecConfig.get_high_security_config()
PERFORMANCE_CONFIG = ChakraSecConfig.get_performance_config()
