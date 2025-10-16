"""
ChakraSec Dynamic Matrix Puzzle System
Implements per-second changing cryptographic puzzles inspired by Abhimanyu Chakravyuh
"""

import time
import hmac
import hashlib
import secrets
import numpy as np
from typing import Tuple, Dict, Any, Optional, List
from dataclasses import dataclass
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

@dataclass
class PuzzleChallenge:
    """A dynamic puzzle challenge"""
    layer_id: int
    time_window: int
    matrix_seed: bytes
    expected_value: int
    difficulty: int
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "layer_id": self.layer_id,
            "time_window": self.time_window,
            "matrix_seed": self.matrix_seed.hex(),
            "expected_value": self.expected_value,
            "difficulty": self.difficulty
        }

@dataclass
class PuzzleProof:
    """Client's proof of puzzle solution"""
    time_window: int
    computed_value: int
    mac: bytes
    client_seed: bytes
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "time_window": self.time_window,
            "computed_value": self.computed_value,
            "mac": self.mac.hex(),
            "client_seed": self.client_seed.hex()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PuzzleProof':
        return cls(
            time_window=data["time_window"],
            computed_value=data["computed_value"],
            mac=bytes.fromhex(data["mac"]),
            client_seed=bytes.fromhex(data["client_seed"])
        )

class MatrixPuzzle:
    """
    Dynamic matrix puzzle system that changes every W seconds
    Inspired by the Abhimanyu Chakravyuh's time-varying nature
    """
    
    def __init__(self, master_secret: bytes, window_seconds: int = 1, drift_tolerance: int = 1):
        """
        Initialize matrix puzzle system
        
        Args:
            master_secret: Server's master secret K_sys
            window_seconds: Time window W in seconds (default 1)
            drift_tolerance: Allow ±drift_tolerance windows for network delays
        """
        self.master_secret = master_secret
        self.window_seconds = window_seconds
        self.drift_tolerance = drift_tolerance
        
        # Pre-compute secret matrix A for strong puzzle function
        self._secret_matrix = self._derive_secret_matrix()
    
    def _derive_secret_matrix(self) -> np.ndarray:
        """Derive secret matrix A from master secret for strong puzzle function"""
        # Use HKDF to expand master secret into matrix elements
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=8 * 64 * 4,  # 8x64 matrix of 32-bit integers
            salt=b"chakrasec-matrix-a",
            info=b"secret-matrix-derivation"
        )
        matrix_bytes = hkdf.derive(self.master_secret)
        
        # Convert to 8x64 matrix of uint32 values
        matrix_ints = np.frombuffer(matrix_bytes, dtype=np.uint32)
        return matrix_ints.reshape(8, 64)
    
    def _get_time_window(self, timestamp: Optional[float] = None) -> int:
        """Get current time window"""
        if timestamp is None:
            timestamp = time.time()
        return int(timestamp // self.window_seconds)
    
    def _generate_matrix(self, client_seed: bytes, layer_id: int, time_window: int) -> np.ndarray:
        """
        Generate 8x8 matrix for given parameters
        
        Args:
            client_seed: Client's seed S_u
            layer_id: Layer identifier
            time_window: Time window t_w
            
        Returns:
            8x8 matrix of bytes
        """
        # Create deterministic seed
        time_bytes = time_window.to_bytes(8, 'big')
        layer_bytes = layer_id.to_bytes(4, 'big')
        
        # HMAC-based seed generation
        seed_data = hmac.new(
            self.master_secret + b"matrix" + layer_bytes,
            client_seed + time_bytes,
            hashlib.sha256
        ).digest()
        
        # Expand seed using HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,  # 64 bytes for 8x8 matrix
            salt=b"chakrasec-matrix-expand",
            info=b"matrix-generation"
        )
        matrix_bytes = hkdf.derive(seed_data)
        
        # Reshape to 8x8 matrix
        return np.frombuffer(matrix_bytes, dtype=np.uint8).reshape(8, 8)
    
    def _compute_simple_puzzle(self, matrix: np.ndarray) -> int:
        """
        Simple puzzle function: compute row parities
        Returns 8-bit value (low entropy but fast)
        """
        row_parities = []
        for row in matrix:
            parity = 0
            for byte_val in row:
                parity ^= bin(byte_val).count('1') % 2
            row_parities.append(parity)
        
        # Combine row parities into single byte
        result = 0
        for i, parity in enumerate(row_parities):
            result |= (parity << i)
        
        return result
    
    def _compute_strong_puzzle(self, matrix: np.ndarray) -> int:
        """
        Strong puzzle function: matrix multiplication with secret matrix A
        Returns 32-bit value (high entropy)
        """
        # Flatten matrix to 64-element vector
        matrix_vector = matrix.flatten().astype(np.uint32)
        
        # Multiply with secret matrix A (8x64) to get 8 values
        result_vector = np.dot(self._secret_matrix, matrix_vector)
        
        # Combine results with XOR and modular arithmetic
        result = 0
        for i, val in enumerate(result_vector):
            # Ensure values stay within 32-bit range
            val_mod = int(val) % (2**32)
            multiplier = (i + 1) % (2**32)
            product = (val_mod * multiplier) % (2**32)
            result ^= product
        
        return int(result % (2**32))
    
    def _compute_puzzle_value(self, matrix: np.ndarray, difficulty: int) -> int:
        """
        Compute puzzle value based on difficulty level
        
        Args:
            matrix: 8x8 byte matrix
            difficulty: Difficulty level (8=simple, 32=medium, 128=strong)
            
        Returns:
            Puzzle value with specified entropy bits
        """
        if difficulty <= 8:
            return self._compute_simple_puzzle(matrix)
        elif difficulty <= 32:
            # Medium: combine simple and strong approaches
            simple_val = self._compute_simple_puzzle(matrix)
            strong_val = self._compute_strong_puzzle(matrix)
            return (simple_val << 24) | (strong_val & 0xFFFFFF)
        else:
            # Strong: full matrix multiplication
            return self._compute_strong_puzzle(matrix)
    
    def generate_challenge(self, client_seed: bytes, layer_id: int, 
                          difficulty: int = 128) -> PuzzleChallenge:
        """
        Generate a puzzle challenge for the current time window
        
        Args:
            client_seed: Client's seed S_u
            layer_id: Layer identifier
            difficulty: Difficulty level (bits of entropy)
            
        Returns:
            Puzzle challenge
        """
        time_window = self._get_time_window()
        
        # Generate matrix for current time window
        matrix = self._generate_matrix(client_seed, layer_id, time_window)
        
        # Compute expected value
        expected_value = self._compute_puzzle_value(matrix, difficulty)
        
        # Create matrix seed for client (they need this to regenerate matrix)
        matrix_seed = hmac.new(
            self.master_secret,
            client_seed + time_window.to_bytes(8, 'big') + layer_id.to_bytes(4, 'big'),
            hashlib.sha256
        ).digest()[:16]  # 128-bit seed
        
        return PuzzleChallenge(
            layer_id=layer_id,
            time_window=time_window,
            matrix_seed=matrix_seed,
            expected_value=expected_value,
            difficulty=difficulty
        )
    
    def create_proof(self, challenge: PuzzleChallenge, client_seed: bytes, 
                    session_nonce: bytes) -> PuzzleProof:
        """
        Create a proof of puzzle solution (client-side)
        
        Args:
            challenge: Puzzle challenge from server
            client_seed: Client's seed S_u
            session_nonce: Session nonce for MAC binding
            
        Returns:
            Puzzle proof
        """
        # Regenerate matrix using challenge parameters
        matrix = self._generate_matrix(client_seed, challenge.layer_id, challenge.time_window)
        
        # Compute puzzle value
        computed_value = self._compute_puzzle_value(matrix, challenge.difficulty)
        
        # Derive MAC key from client seed and session nonce
        mac_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=session_nonce,
            info=b"cc-proof"
        ).derive(client_seed)
        
        # Create MAC over proof data
        proof_data = (
            session_nonce + 
            challenge.layer_id.to_bytes(4, 'big') + 
            challenge.time_window.to_bytes(8, 'big') + 
            computed_value.to_bytes(4, 'big')
        )
        
        mac = hmac.new(mac_key, proof_data, hashlib.sha256).digest()
        
        return PuzzleProof(
            time_window=challenge.time_window,
            computed_value=computed_value,
            mac=mac,
            client_seed=client_seed
        )
    
    def verify_proof(self, proof: PuzzleProof, challenge: PuzzleChallenge, 
                    session_nonce: bytes) -> bool:
        """
        Verify a puzzle proof (server-side)
        
        Args:
            proof: Client's puzzle proof
            challenge: Original challenge
            session_nonce: Session nonce for MAC verification
            
        Returns:
            True if proof is valid
        """
        try:
            # Check time window is within drift tolerance
            current_window = self._get_time_window()
            window_diff = abs(proof.time_window - current_window)
            if window_diff > self.drift_tolerance:
                return False
            
            # Verify time window matches challenge
            if proof.time_window != challenge.time_window:
                return False
            
            # Regenerate matrix and compute expected value
            matrix = self._generate_matrix(proof.client_seed, challenge.layer_id, proof.time_window)
            expected_value = self._compute_puzzle_value(matrix, challenge.difficulty)
            
            # Verify computed value matches expected
            if proof.computed_value != expected_value:
                return False
            
            # Verify MAC
            mac_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=session_nonce,
                info=b"cc-proof"
            ).derive(proof.client_seed)
            
            proof_data = (
                session_nonce + 
                challenge.layer_id.to_bytes(4, 'big') + 
                proof.time_window.to_bytes(8, 'big') + 
                proof.computed_value.to_bytes(4, 'big')
            )
            
            expected_mac = hmac.new(mac_key, proof_data, hashlib.sha256).digest()
            
            return hmac.compare_digest(proof.mac, expected_mac)
            
        except Exception:
            return False
    
    def get_puzzle_info(self, difficulty: int) -> Dict[str, Any]:
        """Get information about puzzle parameters"""
        return {
            "window_seconds": self.window_seconds,
            "drift_tolerance": self.drift_tolerance,
            "difficulty": difficulty,
            "entropy_bits": min(difficulty, 128),
            "matrix_size": "8x8",
            "algorithm": "HKDF-SHA256 + Matrix Multiplication" if difficulty > 32 else "Row Parity"
        }

class PuzzleManager:
    """Manages multiple puzzle instances for different layers"""
    
    def __init__(self, master_secret: bytes):
        self.master_secret = master_secret
        self.puzzles: Dict[int, MatrixPuzzle] = {}
    
    def get_puzzle(self, layer_id: int, window_seconds: int = 1, 
                  drift_tolerance: int = 1) -> MatrixPuzzle:
        """Get or create puzzle instance for a layer"""
        puzzle_key = (layer_id, window_seconds, drift_tolerance)
        
        if puzzle_key not in self.puzzles:
            # Create layer-specific master secret
            layer_secret = hmac.new(
                self.master_secret,
                f"layer-{layer_id}".encode('utf-8'),
                hashlib.sha256
            ).digest()
            
            self.puzzles[puzzle_key] = MatrixPuzzle(
                layer_secret, window_seconds, drift_tolerance
            )
        
        return self.puzzles[puzzle_key]
    
    def cleanup_old_puzzles(self):
        """Remove unused puzzle instances to free memory"""
        # In a production system, implement LRU cache or time-based cleanup
        pass
