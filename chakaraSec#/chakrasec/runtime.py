"""
ChakraVM: ChakraSec Runtime Environment
Executes protected assets by sequentially decrypting layers after policy verification
"""

import os
import sys
import time
import json
import secrets
import subprocess
import tempfile
from typing import Dict, List, Any, Optional, Callable, Union
from dataclasses import dataclass, field
from enum import Enum
import asyncio
import logging
from pathlib import Path

from .dsl import AssetDefinition, LayerPolicy
from .crypto import CryptoEngine, EncryptedPackage, ShamirSecretSharing
from .gate_evaluator import GateEvaluator, ProofRequest, ReleaseToken, VerificationResult
from .compiler import ChakraComp

class ExecutionStatus(Enum):
    """Status of asset execution"""
    PENDING = "pending"
    AUTHENTICATING = "authenticating"
    DECRYPTING = "decrypting"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    DENIED = "denied"

@dataclass
class ExecutionContext:
    """Context for asset execution"""
    package_id: str
    session_nonce: bytes
    current_layer: int
    total_layers: int
    decrypted_layers: List[int] = field(default_factory=list)
    failed_layers: List[int] = field(default_factory=list)
    status: ExecutionStatus = ExecutionStatus.PENDING
    start_time: float = field(default_factory=time.time)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "package_id": self.package_id,
            "session_nonce": self.session_nonce.hex(),
            "current_layer": self.current_layer,
            "total_layers": self.total_layers,
            "decrypted_layers": self.decrypted_layers,
            "failed_layers": self.failed_layers,
            "status": self.status.value,
            "start_time": self.start_time
        }

@dataclass
class ExecutionResult:
    """Result of asset execution"""
    success: bool
    output: Any = None
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    execution_time: float = 0.0
    layers_decrypted: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "output": str(self.output) if self.output is not None else None,
            "errors": self.errors,
            "warnings": self.warnings,
            "execution_time": self.execution_time,
            "layers_decrypted": self.layers_decrypted
        }

class SandboxManager:
    """Manages sandboxed execution of decrypted code"""
    
    def __init__(self, temp_dir: Optional[str] = None):
        self.temp_dir = Path(temp_dir) if temp_dir else Path(tempfile.gettempdir())
        self.active_sandboxes: Dict[str, Dict[str, Any]] = {}
    
    def create_sandbox(self, sandbox_id: str) -> Path:
        """Create isolated sandbox directory"""
        sandbox_path = self.temp_dir / f"chakra_sandbox_{sandbox_id}"
        sandbox_path.mkdir(exist_ok=True, parents=True)
        
        self.active_sandboxes[sandbox_id] = {
            "path": sandbox_path,
            "created_at": time.time(),
            "processes": []
        }
        
        return sandbox_path
    
    def execute_in_sandbox(self, sandbox_id: str, code: bytes, 
                          code_type: str = "python") -> subprocess.CompletedProcess:
        """Execute code in sandbox with restrictions"""
        if sandbox_id not in self.active_sandboxes:
            raise ValueError(f"Sandbox {sandbox_id} not found")
        
        sandbox_path = self.active_sandboxes[sandbox_id]["path"]
        
        # Write code to temporary file
        if code_type == "python":
            code_file = sandbox_path / "main.py"
            code_file.write_bytes(code)
            
            # Execute with restrictions
            cmd = [
                sys.executable, "-c", 
                f"exec(open('{code_file}').read())"
            ]
        else:
            raise ValueError(f"Unsupported code type: {code_type}")
        
        # Set environment restrictions
        env = os.environ.copy()
        env["PYTHONPATH"] = str(sandbox_path)
        
        # Execute with timeout and resource limits
        try:
            result = subprocess.run(
                cmd,
                cwd=sandbox_path,
                env=env,
                capture_output=True,
                text=True,
                timeout=30,  # 30 second timeout
                check=False
            )
            return result
        except subprocess.TimeoutExpired:
            raise TimeoutError("Code execution timed out")
    
    def cleanup_sandbox(self, sandbox_id: str):
        """Clean up sandbox resources"""
        if sandbox_id in self.active_sandboxes:
            sandbox_info = self.active_sandboxes[sandbox_id]
            sandbox_path = sandbox_info["path"]
            
            # Kill any running processes
            for proc in sandbox_info["processes"]:
                try:
                    proc.terminate()
                except:
                    pass
            
            # Remove sandbox directory
            try:
                import shutil
                shutil.rmtree(sandbox_path)
            except:
                pass
            
            del self.active_sandboxes[sandbox_id]

class ProofCollector:
    """Collects proofs from various sources for policy verification"""
    
    def __init__(self):
        self.proof_handlers: Dict[str, Callable] = {
            "mfa": self._collect_mfa_proof,
            "device": self._collect_device_proof,
            "geo": self._collect_geo_proof,
            "puzzle": self._collect_puzzle_proof,
            "threshold": self._collect_threshold_proof,
            "hsm": self._collect_hsm_proof
        }
    
    async def collect_proofs_for_layer(self, layer_policy: LayerPolicy, 
                                     context: ExecutionContext) -> Dict[str, Any]:
        """Collect all required proofs for a layer"""
        proofs = {}
        
        for rule in layer_policy.rules:
            atom_type = rule.atom.value.lower()
            
            if atom_type in self.proof_handlers:
                try:
                    proof = await self.proof_handlers[atom_type](rule, context)
                    proofs[atom_type] = proof
                except Exception as e:
                    logging.error(f"Failed to collect {atom_type} proof: {e}")
                    # Continue collecting other proofs
        
        return proofs
    
    async def _collect_mfa_proof(self, rule, context) -> Dict[str, Any]:
        """Collect MFA proof (interactive)"""
        required_level = rule.params.get("level", 1)
        
        # In a real implementation, this would integrate with MFA providers
        print(f"MFA Level {required_level} required for Layer {context.current_layer}")
        totp_code = input("Enter TOTP code: ")
        
        return {
            "level": required_level,
            "totp_code": totp_code,
            "timestamp": time.time()
        }
    
    async def _collect_device_proof(self, rule, context) -> Dict[str, Any]:
        """Collect device attestation proof"""
        required_pubkey = rule.params.get("pubkey")
        
        # In a real implementation, this would use device TPM/secure enclave
        return {
            "pubkey": required_pubkey,
            "signature": "mock_device_signature",
            "challenge": context.session_nonce.hex()
        }
    
    async def _collect_geo_proof(self, rule, context) -> Dict[str, Any]:
        """Collect geolocation proof"""
        # In a real implementation, this would use GPS/network location
        return {
            "lat": rule.params.get("lat", 0.0),
            "lon": rule.params.get("lon", 0.0),
            "accuracy": 10.0,
            "timestamp": time.time()
        }
    
    async def _collect_puzzle_proof(self, rule, context) -> Dict[str, Any]:
        """Collect puzzle solution proof"""
        from .puzzle import MatrixPuzzle, PuzzleManager
        
        # Create puzzle manager with client seed
        client_seed = secrets.token_bytes(32)
        puzzle_manager = PuzzleManager(b"client_master_secret")  # In production, use proper client secret
        
        difficulty = rule.params.get("difficulty", 128)
        puzzle = puzzle_manager.get_puzzle(context.current_layer)
        
        # Generate challenge
        challenge = puzzle.generate_challenge(client_seed, context.current_layer, difficulty)
        
        # Create proof
        proof = puzzle.create_proof(challenge, client_seed, context.session_nonce)
        
        return proof.to_dict()
    
    async def _collect_threshold_proof(self, rule, context) -> Dict[str, Any]:
        """Collect threshold/custodian proof"""
        threshold = rule.params.get("threshold", 2)
        custodians = rule.params.get("custodians", [])
        
        # In a real implementation, this would contact custodians
        approvals = []
        for i, custodian_id in enumerate(custodians[:threshold]):
            approvals.append({
                "custodian_id": custodian_id,
                "signature": f"mock_signature_{i}",
                "timestamp": time.time()
            })
        
        return {
            "threshold": threshold,
            "approvals": approvals
        }
    
    async def _collect_hsm_proof(self, rule, context) -> Dict[str, Any]:
        """Collect HSM proof"""
        key_id = rule.params.get("key_id")
        
        # In a real implementation, this would interact with HSM
        return {
            "key_id": key_id,
            "signature": "mock_hsm_signature",
            "challenge": context.session_nonce.hex()
        }

class ChakraVM:
    """
    ChakraVM Runtime - Executes protected assets through sequential layer decryption
    """
    
    def __init__(self, gate_evaluator: GateEvaluator, 
                 enable_sandbox: bool = True):
        """
        Initialize ChakraVM
        
        Args:
            gate_evaluator: Gate Evaluator service for proof verification
            enable_sandbox: Whether to enable sandboxed execution
        """
        self.gate_evaluator = gate_evaluator
        self.crypto = CryptoEngine()
        self.shamir = ShamirSecretSharing()
        self.enable_sandbox = enable_sandbox
        
        if enable_sandbox:
            self.sandbox_manager = SandboxManager()
        
        self.proof_collector = ProofCollector()
        self.active_executions: Dict[str, ExecutionContext] = {}
        
        # Setup logging
        self.logger = logging.getLogger("ChakraVM")
    
    async def execute_package(self, package_path: str, 
                            client_info: Dict[str, Any],
                            custodian_shares: Optional[Dict[int, List[Dict[str, Any]]]] = None) -> ExecutionResult:
        """
        Execute a protected package through the complete ChakraSec flow
        
        Args:
            package_path: Path to .ccv package file
            client_info: Client information for verification
            custodian_shares: Optional custodian shares for key reconstruction
            
        Returns:
            Execution result
        """
        start_time = time.time()
        
        try:
            # Load and verify package
            compiler = ChakraComp()
            package = compiler.load_package(package_path)
            
            # Start verification session
            session_nonce = self.gate_evaluator.start_verification_session(
                package.package_id, client_info
            )
            
            # Create execution context
            context = ExecutionContext(
                package_id=package.package_id,
                session_nonce=session_nonce,
                current_layer=len(package.metadata),  # Start from outermost layer
                total_layers=len(package.metadata),
                status=ExecutionStatus.AUTHENTICATING
            )
            
            self.active_executions[package.package_id] = context
            
            # Sequential layer decryption (L7 -> L1)
            current_payload = package.outer_blob
            decrypted_keys = []
            
            for layer_idx in range(len(package.metadata) - 1, -1, -1):  # Reverse order
                layer_metadata = package.metadata[layer_idx]
                layer_id = layer_metadata.layer_id
                
                context.current_layer = layer_id
                context.status = ExecutionStatus.AUTHENTICATING
                
                self.logger.info(f"Processing layer {layer_id} for package {package.package_id}")
                
                # Load layer policy (in production, extract from metadata)
                layer_policy = self._extract_layer_policy(layer_metadata)
                
                # Collect proofs for this layer
                proofs = await self.proof_collector.collect_proofs_for_layer(layer_policy, context)
                
                # Create proof request
                proof_request = ProofRequest(
                    package_id=package.package_id,
                    layer_id=layer_id,
                    session_nonce=session_nonce,
                    proofs=proofs,
                    client_info=client_info
                )
                
                # Verify proofs with Gate Evaluator
                verification_result = await self.gate_evaluator.verify_layer_proofs(
                    proof_request, layer_policy
                )
                
                if not verification_result.success:
                    context.failed_layers.append(layer_id)
                    context.status = ExecutionStatus.FAILED
                    
                    # Handle failure action
                    return await self._handle_verification_failure(
                        verification_result, context, start_time
                    )
                
                # Get layer key using release token
                layer_key = await self._get_layer_key(
                    verification_result.token, layer_metadata, custodian_shares
                )
                
                if not layer_key:
                    context.failed_layers.append(layer_id)
                    context.status = ExecutionStatus.FAILED
                    return ExecutionResult(
                        success=False,
                        errors=[f"Failed to obtain key for layer {layer_id}"],
                        execution_time=time.time() - start_time,
                        layers_decrypted=len(context.decrypted_layers)
                    )
                
                # Decrypt layer
                context.status = ExecutionStatus.DECRYPTING
                try:
                    current_payload = self._decrypt_layer(
                        current_payload, layer_key, layer_metadata
                    )
                    context.decrypted_layers.append(layer_id)
                    decrypted_keys.append(layer_key)
                    
                    # Zeroize key after use
                    self.crypto.zeroize(bytearray(layer_key))
                    
                except Exception as e:
                    context.failed_layers.append(layer_id)
                    context.status = ExecutionStatus.FAILED
                    return ExecutionResult(
                        success=False,
                        errors=[f"Decryption failed for layer {layer_id}: {e}"],
                        execution_time=time.time() - start_time,
                        layers_decrypted=len(context.decrypted_layers)
                    )
            
            # All layers decrypted successfully - execute payload
            context.status = ExecutionStatus.EXECUTING
            execution_output = await self._execute_payload(current_payload, context)
            
            context.status = ExecutionStatus.COMPLETED
            
            # Clean up
            del self.active_executions[package.package_id]
            
            return ExecutionResult(
                success=True,
                output=execution_output,
                execution_time=time.time() - start_time,
                layers_decrypted=len(context.decrypted_layers)
            )
        
        except Exception as e:
            self.logger.error(f"Execution failed: {e}")
            
            if package.package_id in self.active_executions:
                del self.active_executions[package.package_id]
            
            return ExecutionResult(
                success=False,
                errors=[f"Execution error: {str(e)}"],
                execution_time=time.time() - start_time
            )
    
    def _extract_layer_policy(self, layer_metadata) -> LayerPolicy:
        """Extract layer policy from metadata (simplified)"""
        # In a real implementation, this would parse the policy from metadata
        # For now, create a basic policy
        from .dsl import LayerPolicy, PolicyRule, PolicyAtom, ActionType
        
        policy = LayerPolicy(
            layer_id=layer_metadata.layer_id,
            action_on_fail=ActionType.DENY
        )
        
        # Add basic rules based on layer
        if layer_metadata.layer_id >= 5:  # Outer layers
            policy.rules.append(PolicyRule(PolicyAtom.PUZZLE, {"type": "matrix", "difficulty": 128}))
        
        if layer_metadata.layer_id <= 3:  # Inner layers  
            policy.rules.append(PolicyRule(PolicyAtom.MFA, {"level": 2}))
        
        return policy
    
    async def _get_layer_key(self, token: ReleaseToken, layer_metadata,
                           custodian_shares: Optional[Dict[int, List[Dict[str, Any]]]]) -> Optional[bytes]:
        """Get layer key using release token"""
        
        # Validate token
        validated_token = self.gate_evaluator.validate_and_consume_token(
            token.token_id, token.session_nonce
        )
        
        if not validated_token:
            return None
        
        # Check if this layer uses custodian shares
        if custodian_shares and token.layer_id in custodian_shares:
            # Reconstruct key from custodian shares
            shares_data = custodian_shares[token.layer_id]
            
            # Convert to format expected by Shamir reconstruction
            shares = []
            for share_data in shares_data:
                share_id = share_data["share_id"]
                share_bytes = bytes.fromhex(share_data["share_data"])
                shares.append((share_id, share_bytes))
            
            # Determine threshold (simplified - should be in metadata)
            threshold = len(shares)  # Use all shares for now
            
            try:
                reconstructed_key = self.shamir.reconstruct_secret(shares, threshold)
                return reconstructed_key
            except Exception as e:
                self.logger.error(f"Key reconstruction failed: {e}")
                return None
        else:
            # For this demo, generate a deterministic key from token
            # In production, the GE would provide the actual key
            key_material = (
                token.token_id.encode() + 
                token.package_id.encode() + 
                str(token.layer_id).encode()
            )
            return self.crypto.derive_key(
                self.gate_evaluator.master_secret,
                b"layer_key_derivation",
                key_material
            )
    
    def _decrypt_layer(self, encrypted_payload: bytes, key: bytes, 
                      layer_metadata) -> bytes:
        """Decrypt a single layer"""
        # Extract nonce and ciphertext
        nonce = encrypted_payload[:self.crypto.nonce_size]
        ciphertext = encrypted_payload[self.crypto.nonce_size:]
        
        # Verify nonce matches metadata
        if nonce != layer_metadata.nonce:
            raise ValueError(f"Nonce mismatch for layer {layer_metadata.layer_id}")
        
        # Decrypt
        return self.crypto.decrypt_layer(
            key, nonce, ciphertext, layer_metadata.policy_hash
        )
    
    async def _execute_payload(self, payload: bytes, context: ExecutionContext) -> Any:
        """Execute decrypted payload in sandbox"""
        
        if self.enable_sandbox:
            # Execute in sandbox
            sandbox_id = f"{context.package_id}_{int(time.time())}"
            
            try:
                sandbox_path = self.sandbox_manager.create_sandbox(sandbox_id)
                result = self.sandbox_manager.execute_in_sandbox(
                    sandbox_id, payload, "python"
                )
                
                output = {
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "returncode": result.returncode
                }
                
                return output
            
            finally:
                self.sandbox_manager.cleanup_sandbox(sandbox_id)
        else:
            # Direct execution (unsafe - for demo only)
            try:
                # Treat payload as Python code
                code_str = payload.decode('utf-8')
                
                # Create restricted globals
                restricted_globals = {
                    "__builtins__": {
                        "print": print,
                        "len": len,
                        "str": str,
                        "int": int,
                        "float": float,
                        "list": list,
                        "dict": dict,
                    }
                }
                
                # Execute code
                exec(code_str, restricted_globals)
                return {"status": "executed", "globals": list(restricted_globals.keys())}
                
            except Exception as e:
                return {"error": str(e)}
    
    async def _handle_verification_failure(self, verification_result: VerificationResult,
                                         context: ExecutionContext, start_time: float) -> ExecutionResult:
        """Handle verification failure according to policy"""
        
        if verification_result.action.value == "RETURN_DECOY":
            # Return decoy response
            decoy_id = verification_result.action_params.get("decoy_id", "default")
            decoy_response = self._get_decoy_response(decoy_id)
            
            return ExecutionResult(
                success=True,  # Appears successful to attacker
                output=decoy_response,
                warnings=["Decoy response returned due to verification failure"],
                execution_time=time.time() - start_time,
                layers_decrypted=len(context.decrypted_layers)
            )
        
        elif verification_result.action.value == "ALERT":
            # Trigger alert
            alert_group = verification_result.action_params.get("group", "security")
            self._trigger_alert(alert_group, context, verification_result.errors)
        
        # Default: deny access
        return ExecutionResult(
            success=False,
            errors=verification_result.errors,
            execution_time=time.time() - start_time,
            layers_decrypted=len(context.decrypted_layers)
        )
    
    def _get_decoy_response(self, decoy_id: str) -> Any:
        """Get decoy response for failed verification"""
        decoys = {
            "default": {"message": "Access granted", "data": "fake_sensitive_data"},
            "financial": {"balance": 1000000, "account": "FAKE123456"},
            "medical": {"patient_id": "P123456", "diagnosis": "Common Cold"}
        }
        
        return decoys.get(decoy_id, decoys["default"])
    
    def _trigger_alert(self, alert_group: str, context: ExecutionContext, errors: List[str]):
        """Trigger security alert"""
        alert_data = {
            "timestamp": time.time(),
            "package_id": context.package_id,
            "layer_id": context.current_layer,
            "alert_group": alert_group,
            "errors": errors,
            "session_nonce": context.session_nonce.hex()
        }
        
        # In production, send to SIEM/alerting system
        self.logger.warning(f"SECURITY ALERT [{alert_group}]: {alert_data}")
    
    def get_execution_status(self, package_id: str) -> Optional[ExecutionContext]:
        """Get current execution status"""
        return self.active_executions.get(package_id)
    
    def get_runtime_statistics(self) -> Dict[str, Any]:
        """Get runtime statistics"""
        return {
            "active_executions": len(self.active_executions),
            "sandbox_enabled": self.enable_sandbox,
            "total_sandboxes": len(self.sandbox_manager.active_sandboxes) if self.enable_sandbox else 0
        }


