"""
ChakraSec Cryptographic Engine
Implements core cryptographic operations for 7-layer protection
"""

import os
import hashlib
import hmac
import secrets
from typing import Tuple, List, Dict, Any, Optional
from dataclasses import dataclass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
import nacl.secret
import nacl.utils
import nacl.encoding

@dataclass
class LayerMetadata:
    """Metadata for a single encryption layer"""
    layer_id: int
    policy_hash: bytes
    commit: bytes
    wrap_salt: bytes
    nonce: bytes
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "layer_id": self.layer_id,
            "policy_hash": self.policy_hash.hex(),
            "commit": self.commit.hex(),
            "wrap_salt": self.wrap_salt.hex(),
            "nonce": self.nonce.hex()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'LayerMetadata':
        return cls(
            layer_id=data["layer_id"],
            policy_hash=bytes.fromhex(data["policy_hash"]),
            commit=bytes.fromhex(data["commit"]),
            wrap_salt=bytes.fromhex(data["wrap_salt"]),
            nonce=bytes.fromhex(data["nonce"])
        )

@dataclass
class EncryptedPackage:
    """Complete encrypted package (.ccv format)"""
    package_id: str
    outer_blob: bytes
    metadata: List[LayerMetadata]
    signature: bytes
    public_key: bytes
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "package_id": self.package_id,
            "outer_blob": self.outer_blob.hex(),
            "metadata": [meta.to_dict() for meta in self.metadata],
            "signature": self.signature.hex(),
            "public_key": self.public_key.hex()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'EncryptedPackage':
        return cls(
            package_id=data["package_id"],
            outer_blob=bytes.fromhex(data["outer_blob"]),
            metadata=[LayerMetadata.from_dict(meta) for meta in data["metadata"]],
            signature=bytes.fromhex(data["signature"]),
            public_key=bytes.fromhex(data["public_key"])
        )

class CryptoEngine:
    """Core cryptographic operations for ChakraSec"""
    
    def __init__(self):
        self.key_size = 32  # 256-bit keys
        self.nonce_size = 12  # 96-bit nonces for AES-GCM
        
    def generate_key(self) -> bytes:
        """Generate a cryptographically secure random key"""
        return secrets.token_bytes(self.key_size)
    
    def generate_nonce(self) -> bytes:
        """Generate a cryptographically secure random nonce"""
        return secrets.token_bytes(self.nonce_size)
    
    def compute_commit(self, key: bytes, metadata: bytes) -> bytes:
        """Compute commitment hash for a key and metadata"""
        return hashlib.sha256(key + metadata).digest()
    
    def encrypt_layer(self, key: bytes, plaintext: bytes, aad: bytes) -> Tuple[bytes, bytes]:
        """Encrypt a single layer with AES-GCM"""
        nonce = self.generate_nonce()
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
        return nonce, ciphertext
    
    def decrypt_layer(self, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        """Decrypt a single layer with AES-GCM"""
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, aad)
    
    def encrypt_payload(self, payload: bytes, keys: List[bytes], 
                       policies: List[Dict[str, Any]]) -> Tuple[bytes, List[LayerMetadata]]:
        """
        Encrypt payload with N layers (inner->outer)
        Returns outer blob and metadata for each layer
        """
        if len(keys) != len(policies):
            raise ValueError("Number of keys must match number of policies")
        
        current_payload = payload
        metadata_list = []
        
        # Encrypt from inner (L1) to outer (L7)
        for i, (key, policy) in enumerate(zip(keys, policies)):
            layer_id = i + 1
            
            # Create metadata for this layer
            policy_bytes = str(policy).encode('utf-8')
            policy_hash = hashlib.sha256(policy_bytes).digest()
            commit = self.compute_commit(key, policy_bytes)
            wrap_salt = secrets.token_bytes(16)
            
            # Encrypt with AES-GCM
            nonce, ciphertext = self.encrypt_layer(key, current_payload, policy_hash)
            
            # Prepend nonce to ciphertext
            current_payload = nonce + ciphertext
            
            # Store metadata
            metadata = LayerMetadata(
                layer_id=layer_id,
                policy_hash=policy_hash,
                commit=commit,
                wrap_salt=wrap_salt,
                nonce=nonce
            )
            metadata_list.append(metadata)
        
        return current_payload, metadata_list
    
    def decrypt_payload(self, outer_blob: bytes, keys: List[bytes], 
                       metadata_list: List[LayerMetadata]) -> bytes:
        """
        Decrypt payload by unwrapping N layers (outer->inner)
        Keys must be provided in reverse order (L7->L1)
        """
        if len(keys) != len(metadata_list):
            raise ValueError("Number of keys must match number of metadata entries")
        
        current_payload = outer_blob
        
        # Decrypt from outer (L7) to inner (L1)
        for key, metadata in zip(keys, reversed(metadata_list)):
            # Extract nonce and ciphertext
            nonce = current_payload[:self.nonce_size]
            ciphertext = current_payload[self.nonce_size:]
            
            # Verify nonce matches metadata
            if nonce != metadata.nonce:
                raise ValueError(f"Nonce mismatch for layer {metadata.layer_id}")
            
            # Decrypt layer
            current_payload = self.decrypt_layer(
                key, nonce, ciphertext, metadata.policy_hash
            )
        
        return current_payload
    
    def generate_signing_key(self) -> Tuple[Ed25519PrivateKey, Ed25519PublicKey]:
        """Generate Ed25519 signing key pair"""
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key
    
    def sign_package(self, private_key: Ed25519PrivateKey, package_data: bytes) -> bytes:
        """Sign package data with Ed25519"""
        return private_key.sign(package_data)
    
    def verify_package(self, public_key: Ed25519PublicKey, signature: bytes, 
                      package_data: bytes) -> bool:
        """Verify package signature with Ed25519"""
        try:
            public_key.verify(signature, package_data)
            return True
        except InvalidSignature:
            return False
    
    def derive_key(self, master_key: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
        """Derive key using HKDF-SHA256"""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            info=info,
        )
        return hkdf.derive(master_key)
    
    def secure_compare(self, a: bytes, b: bytes) -> bool:
        """Constant-time comparison to prevent timing attacks"""
        return hmac.compare_digest(a, b)
    
    def zeroize(self, data: bytearray):
        """Securely zero out sensitive data"""
        if isinstance(data, bytearray):
            for i in range(len(data)):
                data[i] = 0
        # Note: Python strings/bytes are immutable, so we can't truly zeroize them
        # In production, use ctypes or specialized libraries for true memory clearing

class ShamirSecretSharing:
    """Shamir Secret Sharing implementation for custodian keys"""
    
    def __init__(self):
        # Using a large prime for the finite field
        self.prime = 2**256 - 189  # A 256-bit prime
    
    def _mod_inverse(self, a: int, m: int) -> int:
        """Compute modular inverse using extended Euclidean algorithm"""
        if a < 0:
            a = (a % m + m) % m
        
        # Extended Euclidean Algorithm
        def extended_gcd(a, b):
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd, x, y
        
        gcd, x, _ = extended_gcd(a, m)
        if gcd != 1:
            raise ValueError("Modular inverse does not exist")
        return (x % m + m) % m
    
    def _evaluate_polynomial(self, coefficients: List[int], x: int) -> int:
        """Evaluate polynomial at point x using Horner's method"""
        result = 0
        for coeff in reversed(coefficients):
            result = (result * x + coeff) % self.prime
        return result
    
    def split_secret(self, secret: bytes, threshold: int, num_shares: int) -> List[Tuple[int, bytes]]:
        """
        Split secret into shares using Shamir's scheme
        Returns list of (share_id, share_value) tuples
        """
        if threshold > num_shares:
            raise ValueError("Threshold cannot exceed number of shares")
        if threshold < 2:
            raise ValueError("Threshold must be at least 2")
        
        # Convert secret to integer
        secret_int = int.from_bytes(secret, 'big')
        if secret_int >= self.prime:
            raise ValueError("Secret too large for field")
        
        # Generate random coefficients for polynomial
        coefficients = [secret_int]  # a0 = secret
        for _ in range(threshold - 1):
            coefficients.append(secrets.randbelow(self.prime))
        
        # Generate shares
        shares = []
        for i in range(1, num_shares + 1):
            share_value = self._evaluate_polynomial(coefficients, i)
            share_bytes = share_value.to_bytes(32, 'big')
            shares.append((i, share_bytes))
        
        return shares
    
    def reconstruct_secret(self, shares: List[Tuple[int, bytes]], threshold: int) -> bytes:
        """
        Reconstruct secret from threshold number of shares
        """
        if len(shares) < threshold:
            raise ValueError(f"Need at least {threshold} shares, got {len(shares)}")
        
        # Use first 'threshold' shares
        shares = shares[:threshold]
        
        # Convert shares to integers
        points = []
        for share_id, share_bytes in shares:
            share_int = int.from_bytes(share_bytes, 'big')
            points.append((share_id, share_int))
        
        # Lagrange interpolation to find secret (coefficient a0)
        secret = 0
        for i, (xi, yi) in enumerate(points):
            # Compute Lagrange basis polynomial li(0)
            numerator = 1
            denominator = 1
            
            for j, (xj, _) in enumerate(points):
                if i != j:
                    numerator = (numerator * (-xj)) % self.prime
                    denominator = (denominator * (xi - xj)) % self.prime
            
            # Compute li(0) = numerator / denominator
            lagrange_coeff = (numerator * self._mod_inverse(denominator, self.prime)) % self.prime
            secret = (secret + yi * lagrange_coeff) % self.prime
        
        # Convert back to bytes
        return secret.to_bytes(32, 'big')
    
    def verify_share(self, share: Tuple[int, bytes], public_commitments: List[bytes]) -> bool:
        """
        Verify a share against public commitments (Feldman's VSS)
        This is a simplified version - full implementation would use elliptic curves
        """
        # For now, just verify the share format
        share_id, share_bytes = share
        return (1 <= share_id <= 255 and 
                len(share_bytes) == 32 and 
                int.from_bytes(share_bytes, 'big') < self.prime)


