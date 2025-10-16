"""
ChakraComp: ChakraSec Compiler
Compiles protected assets into 7-layer encrypted .ccv packages
"""

import json
import hashlib
import secrets
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import os
from pathlib import Path

from .dsl import AssetDefinition, LayerPolicy
from .crypto import CryptoEngine, EncryptedPackage, LayerMetadata, ShamirSecretSharing
from .puzzle import MatrixPuzzle
from cryptography.hazmat.primitives import serialization

@dataclass
class CompilationResult:
    """Result of compilation process"""
    package_id: str
    package_path: str
    success: bool
    errors: List[str] = None
    warnings: List[str] = None
    
    def __post_init__(self):
        if self.errors is None:
            self.errors = []
        if self.warnings is None:
            self.warnings = []

@dataclass
class CustodianShare:
    """Custodian key share information"""
    custodian_id: str
    layer_id: int
    share_id: int
    share_data: bytes
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "custodian_id": self.custodian_id,
            "layer_id": self.layer_id,
            "share_id": self.share_id,
            "share_data": self.share_data.hex()
        }

class ChakraComp:
    """
    ChakraSec Compiler - Transforms source code and policies into protected .ccv packages
    """
    
    def __init__(self, output_dir: str = "dist"):
        self.crypto = CryptoEngine()
        self.shamir = ShamirSecretSharing()
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Generate compiler signing keys
        self.signing_private_key, self.signing_public_key = self.crypto.generate_signing_key()
    
    def compile_asset(self, asset_def: AssetDefinition, source_code: bytes, 
                     custodian_config: Optional[Dict[str, Any]] = None) -> CompilationResult:
        """
        Compile an asset definition and source code into a protected .ccv package
        
        Args:
            asset_def: Asset definition with policies
            source_code: Raw source code to protect
            custodian_config: Optional custodian configuration for key splitting
            
        Returns:
            Compilation result with package information
        """
        try:
            # Generate package ID
            package_id = self._generate_package_id(asset_def.name, source_code)
            
            # Validate asset definition
            validation_errors = self._validate_asset_definition(asset_def)
            if validation_errors:
                return CompilationResult(
                    package_id=package_id,
                    package_path="",
                    success=False,
                    errors=validation_errors
                )
            
            # Generate layer keys
            layer_keys = [self.crypto.generate_key() for _ in range(asset_def.layers)]
            
            # Prepare policies for each layer
            layer_policies = self._prepare_layer_policies(asset_def)
            
            # Handle custodian key splitting if configured
            custodian_shares = {}
            if custodian_config:
                custodian_shares = self._split_keys_for_custodians(
                    layer_keys, asset_def, custodian_config
                )
            
            # Encrypt payload with 7 layers
            outer_blob, metadata_list = self.crypto.encrypt_payload(
                source_code, layer_keys, layer_policies
            )
            
            # Create encrypted package
            package = EncryptedPackage(
                package_id=package_id,
                outer_blob=outer_blob,
                metadata=metadata_list,
                signature=b"",  # Will be set after signing
                public_key=self.signing_public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            )
            
            # Sign the package
            package_data = self._serialize_package_for_signing(package)
            signature = self.crypto.sign_package(self.signing_private_key, package_data)
            package.signature = signature
            
            # Save package to .ccv file
            package_path = self._save_package(package, custodian_shares)
            
            # Generate warnings if any
            warnings = self._generate_warnings(asset_def, custodian_config)
            
            return CompilationResult(
                package_id=package_id,
                package_path=str(package_path),
                success=True,
                warnings=warnings
            )
            
        except Exception as e:
            return CompilationResult(
                package_id=package_id if 'package_id' in locals() else "unknown",
                package_path="",
                success=False,
                errors=[f"Compilation failed: {str(e)}"]
            )
    
    def _generate_package_id(self, asset_name: str, source_code: bytes) -> str:
        """Generate unique package ID"""
        content_hash = hashlib.sha256(source_code).hexdigest()[:16]
        name_hash = hashlib.sha256(asset_name.encode()).hexdigest()[:8]
        return f"chakra_{name_hash}_{content_hash}"
    
    def _validate_asset_definition(self, asset_def: AssetDefinition) -> List[str]:
        """Validate asset definition for compilation"""
        errors = []
        
        # Check layer count
        if asset_def.layers != 7:
            errors.append(f"Asset must have exactly 7 layers, got {asset_def.layers}")
        
        # Check that all layers have policies
        for layer_id in range(1, asset_def.layers + 1):
            if layer_id not in asset_def.layer_policies:
                errors.append(f"Layer {layer_id} missing policy definition")
            else:
                policy = asset_def.layer_policies[layer_id]
                if not policy.rules:
                    errors.append(f"Layer {layer_id} has no policy rules")
        
        # Validate policy rules
        for layer_id, policy in asset_def.layer_policies.items():
            for rule in policy.rules:
                rule_errors = self._validate_policy_rule(rule, layer_id)
                errors.extend(rule_errors)
        
        return errors
    
    def _validate_policy_rule(self, rule, layer_id: int) -> List[str]:
        """Validate individual policy rule"""
        errors = []
        
        # Check required parameters for each atom type
        if rule.atom.value == "MFA":
            if "level" not in rule.params or not isinstance(rule.params["level"], int):
                errors.append(f"Layer {layer_id}: MFA rule requires integer 'level' parameter")
        
        elif rule.atom.value == "DEVICE":
            if "pubkey" not in rule.params or not rule.params["pubkey"]:
                errors.append(f"Layer {layer_id}: DEVICE rule requires 'pubkey' parameter")
        
        elif rule.atom.value == "TIME_WINDOW":
            if "start" not in rule.params or "end" not in rule.params:
                errors.append(f"Layer {layer_id}: TIME_WINDOW rule requires 'start' and 'end' parameters")
        
        elif rule.atom.value == "GEO":
            required = ["lat", "lon", "radius"]
            for param in required:
                if param not in rule.params:
                    errors.append(f"Layer {layer_id}: GEO rule requires '{param}' parameter")
        
        elif rule.atom.value == "THRESHOLD":
            if "threshold" not in rule.params or "custodians" not in rule.params:
                errors.append(f"Layer {layer_id}: THRESHOLD rule requires 'threshold' and 'custodians' parameters")
        
        elif rule.atom.value == "PUZZLE":
            if "type" not in rule.params:
                rule.params["type"] = "matrix"  # Default
            if "difficulty" not in rule.params:
                rule.params["difficulty"] = 128  # Default
        
        return errors
    
    def _prepare_layer_policies(self, asset_def: AssetDefinition) -> List[Dict[str, Any]]:
        """Prepare policy dictionaries for each layer"""
        policies = []
        
        for layer_id in range(1, asset_def.layers + 1):
            if layer_id in asset_def.layer_policies:
                policy_dict = asset_def.layer_policies[layer_id].to_dict()
            else:
                # Default empty policy (should not happen after validation)
                policy_dict = {
                    "layer_id": layer_id,
                    "rules": [],
                    "action_on_fail": "DENY",
                    "fail_params": {}
                }
            
            policies.append(policy_dict)
        
        return policies
    
    def _split_keys_for_custodians(self, layer_keys: List[bytes], asset_def: AssetDefinition,
                                  custodian_config: Dict[str, Any]) -> Dict[int, List[CustodianShare]]:
        """Split layer keys using Shamir secret sharing for custodians"""
        custodian_shares = {}
        
        for layer_id in range(1, asset_def.layers + 1):
            layer_policy = asset_def.layer_policies.get(layer_id)
            if not layer_policy:
                continue
            
            # Check if this layer uses threshold/custodian policy
            threshold_rule = None
            for rule in layer_policy.rules:
                if rule.atom.value == "THRESHOLD":
                    threshold_rule = rule
                    break
            
            if threshold_rule:
                threshold = threshold_rule.params["threshold"]
                custodian_ids = threshold_rule.params["custodians"]
                
                if len(custodian_ids) < threshold:
                    raise ValueError(f"Layer {layer_id}: Not enough custodians for threshold")
                
                # Split the key
                key = layer_keys[layer_id - 1]  # 0-indexed
                shares = self.shamir.split_secret(key, threshold, len(custodian_ids))
                
                # Create custodian share objects
                layer_shares = []
                for i, (share_id, share_data) in enumerate(shares):
                    custodian_share = CustodianShare(
                        custodian_id=custodian_ids[i],
                        layer_id=layer_id,
                        share_id=share_id,
                        share_data=share_data
                    )
                    layer_shares.append(custodian_share)
                
                custodian_shares[layer_id] = layer_shares
        
        return custodian_shares
    
    def _serialize_package_for_signing(self, package: EncryptedPackage) -> bytes:
        """Serialize package data for signing (excluding signature field)"""
        # Create a copy without signature for signing
        package_dict = package.to_dict()
        package_dict["signature"] = ""  # Empty signature for signing
        
        # Serialize to canonical JSON
        json_str = json.dumps(package_dict, sort_keys=True, separators=(',', ':'))
        return json_str.encode('utf-8')
    
    def _save_package(self, package: EncryptedPackage, 
                     custodian_shares: Dict[int, List[CustodianShare]]) -> Path:
        """Save encrypted package and custodian shares to files"""
        # Save main package
        package_filename = f"{package.package_id}.ccv"
        package_path = self.output_dir / package_filename
        
        package_data = {
            "header": {
                "magic": "CHAKRASEC",
                "version": "1.0",
                "package_id": package.package_id,
                "signature": package.signature.hex()
            },
            "package": package.to_dict(),
            "custodian_info": {
                layer_id: [share.to_dict() for share in shares]
                for layer_id, shares in custodian_shares.items()
            }
        }
        
        with open(package_path, 'w') as f:
            json.dump(package_data, f, indent=2)
        
        # Save individual custodian share files
        for layer_id, shares in custodian_shares.items():
            for share in shares:
                share_filename = f"{package.package_id}_L{layer_id}_{share.custodian_id}.share"
                share_path = self.output_dir / share_filename
                
                share_data = {
                    "package_id": package.package_id,
                    "layer_id": layer_id,
                    "custodian_id": share.custodian_id,
                    "share_id": share.share_id,
                    "share_data": share.share_data.hex(),
                    "created_at": str(package_data["header"])
                }
                
                with open(share_path, 'w') as f:
                    json.dump(share_data, f, indent=2)
        
        return package_path
    
    def _generate_warnings(self, asset_def: AssetDefinition, 
                          custodian_config: Optional[Dict[str, Any]]) -> List[str]:
        """Generate compilation warnings"""
        warnings = []
        
        # Check for security best practices
        for layer_id, policy in asset_def.layer_policies.items():
            # Warn about single-factor layers
            if len(policy.rules) == 1:
                warnings.append(f"Layer {layer_id} has only one policy rule - consider multi-factor")
            
            # Warn about missing puzzle on outer layers
            if layer_id >= 5:  # Outer layers
                has_puzzle = any(rule.atom.value == "PUZZLE" for rule in policy.rules)
                if not has_puzzle:
                    warnings.append(f"Layer {layer_id} (outer) missing PUZZLE rule - reduces moving target defense")
            
            # Warn about missing MFA on critical layers
            if layer_id <= 3:  # Inner layers
                has_mfa = any(rule.atom.value == "MFA" for rule in policy.rules)
                if not has_mfa:
                    warnings.append(f"Layer {layer_id} (inner) missing MFA rule - reduces human verification")
        
        # Warn about custodian configuration
        if not custodian_config:
            threshold_layers = []
            for layer_id, policy in asset_def.layer_policies.items():
                has_threshold = any(rule.atom.value == "THRESHOLD" for rule in policy.rules)
                if has_threshold:
                    threshold_layers.append(layer_id)
            
            if threshold_layers:
                warnings.append(f"Layers {threshold_layers} use THRESHOLD but no custodian config provided")
        
        return warnings
    
    def load_package(self, package_path: str) -> EncryptedPackage:
        """Load encrypted package from .ccv file"""
        with open(package_path, 'r') as f:
            package_data = json.load(f)
        
        # Verify header
        header = package_data["header"]
        if header["magic"] != "CHAKRASEC":
            raise ValueError("Invalid package format")
        
        # Load package
        package_dict = package_data["package"]
        package = EncryptedPackage.from_dict(package_dict)
        
        # Verify signature
        package_for_verification = EncryptedPackage(
            package_id=package.package_id,
            outer_blob=package.outer_blob,
            metadata=package.metadata,
            signature=b"",  # Empty for verification
            public_key=package.public_key
        )
        
        verification_data = self._serialize_package_for_signing(package_for_verification)
        
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        public_key = Ed25519PublicKey.from_public_bytes(package.public_key)
        
        if not self.crypto.verify_package(public_key, package.signature, verification_data):
            raise ValueError("Package signature verification failed")
        
        return package
    
    def get_compiler_info(self) -> Dict[str, Any]:
        """Get compiler information and statistics"""
        return {
            "version": "1.0",
            "output_directory": str(self.output_dir),
            "signing_public_key": self.signing_public_key.public_bytes_raw().hex(),
            "supported_layers": 7,
            "supported_atoms": [
                "MFA", "DEVICE", "TIME_WINDOW", "GEO", 
                "THRESHOLD", "PUZZLE", "HSM_UNSEAL", 
                "RISK_LEQ", "RATE_LIMIT"
            ]
        }
