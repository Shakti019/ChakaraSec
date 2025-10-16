"""
Gate Evaluator (GE): ChakraSec Policy Verification Service
Verifies proofs and issues single-use release tokens for layer keys
"""

import time
import json
import hmac
import hashlib
import secrets
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import asyncio
from datetime import datetime, timedelta
import logging

from .dsl import PolicyRule, LayerPolicy, PolicyAtom, ActionType
from .crypto import CryptoEngine
from .puzzle import MatrixPuzzle, PuzzleChallenge, PuzzleProof, PuzzleManager

class ProofStatus(Enum):
    """Status of proof verification"""
    PENDING = "pending"
    VERIFIED = "verified"
    FAILED = "failed"
    EXPIRED = "expired"

@dataclass
class ReleaseToken:
    """Single-use token for key release"""
    token_id: str
    package_id: str
    layer_id: int
    session_nonce: bytes
    issued_at: float
    expires_at: float
    used: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "token_id": self.token_id,
            "package_id": self.package_id,
            "layer_id": self.layer_id,
            "session_nonce": self.session_nonce.hex(),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "used": self.used
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ReleaseToken':
        return cls(
            token_id=data["token_id"],
            package_id=data["package_id"],
            layer_id=data["layer_id"],
            session_nonce=bytes.fromhex(data["session_nonce"]),
            issued_at=data["issued_at"],
            expires_at=data["expires_at"],
            used=data.get("used", False)
        )

@dataclass
class ProofRequest:
    """Client's proof submission for a layer"""
    package_id: str
    layer_id: int
    session_nonce: bytes
    proofs: Dict[str, Any]  # Proof data for each policy atom
    client_info: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "package_id": self.package_id,
            "layer_id": self.layer_id,
            "session_nonce": self.session_nonce.hex(),
            "proofs": self.proofs,
            "client_info": self.client_info
        }

@dataclass
class VerificationResult:
    """Result of proof verification"""
    success: bool
    token: Optional[ReleaseToken] = None
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    action: ActionType = ActionType.DENY
    action_params: Dict[str, Any] = field(default_factory=dict)

class SessionManager:
    """Manages active verification sessions"""
    
    def __init__(self, session_timeout: int = 300):  # 5 minutes
        self.sessions: Dict[str, Dict[str, Any]] = {}
        self.session_timeout = session_timeout
    
    def create_session(self, package_id: str, client_info: Dict[str, Any]) -> bytes:
        """Create new verification session"""
        session_nonce = secrets.token_bytes(32)
        session_id = session_nonce.hex()
        
        self.sessions[session_id] = {
            "package_id": package_id,
            "session_nonce": session_nonce,
            "client_info": client_info,
            "created_at": time.time(),
            "verified_layers": set(),
            "failed_attempts": 0
        }
        
        return session_nonce
    
    def get_session(self, session_nonce: bytes) -> Optional[Dict[str, Any]]:
        """Get session by nonce"""
        session_id = session_nonce.hex()
        session = self.sessions.get(session_id)
        
        if session and time.time() - session["created_at"] > self.session_timeout:
            del self.sessions[session_id]
            return None
        
        return session
    
    def mark_layer_verified(self, session_nonce: bytes, layer_id: int):
        """Mark layer as verified in session"""
        session_id = session_nonce.hex()
        if session_id in self.sessions:
            self.sessions[session_id]["verified_layers"].add(layer_id)
    
    def increment_failed_attempts(self, session_nonce: bytes):
        """Increment failed attempt counter"""
        session_id = session_nonce.hex()
        if session_id in self.sessions:
            self.sessions[session_id]["failed_attempts"] += 1
    
    def cleanup_expired_sessions(self):
        """Remove expired sessions"""
        current_time = time.time()
        expired_sessions = [
            session_id for session_id, session in self.sessions.items()
            if current_time - session["created_at"] > self.session_timeout
        ]
        
        for session_id in expired_sessions:
            del self.sessions[session_id]

class RateLimiter:
    """Rate limiting for proof attempts"""
    
    def __init__(self):
        self.attempts: Dict[str, List[float]] = {}
    
    def check_rate_limit(self, client_id: str, max_attempts: int, window_seconds: int) -> bool:
        """Check if client is within rate limits"""
        current_time = time.time()
        
        if client_id not in self.attempts:
            self.attempts[client_id] = []
        
        # Remove old attempts outside window
        self.attempts[client_id] = [
            attempt_time for attempt_time in self.attempts[client_id]
            if current_time - attempt_time < window_seconds
        ]
        
        # Check if under limit
        if len(self.attempts[client_id]) >= max_attempts:
            return False
        
        # Record this attempt
        self.attempts[client_id].append(current_time)
        return True

class GateEvaluator:
    """
    Gate Evaluator Service - Verifies proofs and issues release tokens
    """
    
    def __init__(self, master_secret: bytes, token_lifetime: int = 60):
        """
        Initialize Gate Evaluator
        
        Args:
            master_secret: Master secret for cryptographic operations
            token_lifetime: Token lifetime in seconds
        """
        self.master_secret = master_secret
        self.token_lifetime = token_lifetime
        self.crypto = CryptoEngine()
        self.puzzle_manager = PuzzleManager(master_secret)
        self.session_manager = SessionManager()
        self.rate_limiter = RateLimiter()
        
        # Token storage (in production, use persistent storage)
        self.active_tokens: Dict[str, ReleaseToken] = {}
        
        # Audit log
        self.audit_log: List[Dict[str, Any]] = []
        
        # Setup logging
        self.logger = logging.getLogger("GateEvaluator")
    
    def start_verification_session(self, package_id: str, 
                                 client_info: Dict[str, Any]) -> bytes:
        """Start new verification session"""
        session_nonce = self.session_manager.create_session(package_id, client_info)
        
        self._audit_log("session_started", {
            "package_id": package_id,
            "session_nonce": session_nonce.hex(),
            "client_info": client_info
        })
        
        return session_nonce
    
    async def verify_layer_proofs(self, proof_request: ProofRequest, 
                                layer_policy: LayerPolicy) -> VerificationResult:
        """
        Verify all proofs for a layer and issue release token if successful
        """
        try:
            # Get session
            session = self.session_manager.get_session(proof_request.session_nonce)
            if not session:
                return VerificationResult(
                    success=False,
                    errors=["Invalid or expired session"],
                    action=ActionType.DENY
                )
            
            # Check rate limiting
            client_id = self._get_client_id(proof_request.client_info)
            if not self.rate_limiter.check_rate_limit(client_id, 10, 60):  # 10 attempts per minute
                return VerificationResult(
                    success=False,
                    errors=["Rate limit exceeded"],
                    action=ActionType.DENY
                )
            
            # Verify each policy rule
            verification_results = []
            for rule in layer_policy.rules:
                result = await self._verify_policy_rule(rule, proof_request)
                verification_results.append(result)
            
            # Check if all rules passed
            all_passed = all(result.success for result in verification_results)
            
            if all_passed:
                # Generate release token
                token = self._generate_release_token(
                    proof_request.package_id,
                    proof_request.layer_id,
                    proof_request.session_nonce
                )
                
                # Mark layer as verified
                self.session_manager.mark_layer_verified(
                    proof_request.session_nonce, 
                    proof_request.layer_id
                )
                
                self._audit_log("layer_verified", {
                    "package_id": proof_request.package_id,
                    "layer_id": proof_request.layer_id,
                    "session_nonce": proof_request.session_nonce.hex(),
                    "token_id": token.token_id
                })
                
                return VerificationResult(
                    success=True,
                    token=token,
                    action=ActionType.ALLOW_EXECUTE
                )
            else:
                # Handle failure according to policy
                self.session_manager.increment_failed_attempts(proof_request.session_nonce)
                
                errors = []
                for result in verification_results:
                    errors.extend(result.errors)
                
                self._audit_log("layer_verification_failed", {
                    "package_id": proof_request.package_id,
                    "layer_id": proof_request.layer_id,
                    "session_nonce": proof_request.session_nonce.hex(),
                    "errors": errors
                })
                
                return VerificationResult(
                    success=False,
                    errors=errors,
                    action=layer_policy.action_on_fail,
                    action_params=layer_policy.fail_params
                )
        
        except Exception as e:
            self.logger.error(f"Verification error: {e}")
            return VerificationResult(
                success=False,
                errors=[f"Internal verification error: {str(e)}"],
                action=ActionType.DENY
            )
    
    async def _verify_policy_rule(self, rule: PolicyRule, 
                                proof_request: ProofRequest) -> VerificationResult:
        """Verify individual policy rule"""
        
        if rule.atom == PolicyAtom.MFA:
            return await self._verify_mfa_proof(rule, proof_request)
        
        elif rule.atom == PolicyAtom.DEVICE:
            return await self._verify_device_proof(rule, proof_request)
        
        elif rule.atom == PolicyAtom.TIME_WINDOW:
            return await self._verify_time_window_proof(rule, proof_request)
        
        elif rule.atom == PolicyAtom.GEO:
            return await self._verify_geo_proof(rule, proof_request)
        
        elif rule.atom == PolicyAtom.THRESHOLD:
            return await self._verify_threshold_proof(rule, proof_request)
        
        elif rule.atom == PolicyAtom.PUZZLE:
            return await self._verify_puzzle_proof(rule, proof_request)
        
        elif rule.atom == PolicyAtom.HSM_UNSEAL:
            return await self._verify_hsm_proof(rule, proof_request)
        
        elif rule.atom == PolicyAtom.RISK_LEQ:
            return await self._verify_risk_proof(rule, proof_request)
        
        elif rule.atom == PolicyAtom.RATE_LIMIT:
            return await self._verify_rate_limit_proof(rule, proof_request)
        
        else:
            return VerificationResult(
                success=False,
                errors=[f"Unknown policy atom: {rule.atom}"]
            )
    
    async def _verify_mfa_proof(self, rule: PolicyRule, 
                              proof_request: ProofRequest) -> VerificationResult:
        """Verify MFA proof (TOTP, SMS, etc.)"""
        mfa_proof = proof_request.proofs.get("mfa")
        if not mfa_proof:
            return VerificationResult(
                success=False,
                errors=["MFA proof required"]
            )
        
        required_level = rule.params.get("level", 1)
        provided_level = mfa_proof.get("level", 0)
        
        if provided_level < required_level:
            return VerificationResult(
                success=False,
                errors=[f"MFA level {required_level} required, got {provided_level}"]
            )
        
        # Verify TOTP code (simplified - in production use proper TOTP library)
        totp_code = mfa_proof.get("totp_code")
        if totp_code:
            # This is a simplified verification - use proper TOTP validation
            if len(str(totp_code)) == 6 and str(totp_code).isdigit():
                return VerificationResult(success=True)
        
        return VerificationResult(
            success=False,
            errors=["Invalid MFA proof"]
        )
    
    async def _verify_device_proof(self, rule: PolicyRule, 
                                 proof_request: ProofRequest) -> VerificationResult:
        """Verify device attestation proof"""
        device_proof = proof_request.proofs.get("device")
        if not device_proof:
            return VerificationResult(
                success=False,
                errors=["Device attestation proof required"]
            )
        
        required_pubkey = rule.params.get("pubkey")
        provided_pubkey = device_proof.get("pubkey")
        
        if required_pubkey != provided_pubkey:
            return VerificationResult(
                success=False,
                errors=["Device public key mismatch"]
            )
        
        # Verify signature (simplified)
        signature = device_proof.get("signature")
        challenge = device_proof.get("challenge")
        
        if signature and challenge:
            # In production, verify the signature properly
            return VerificationResult(success=True)
        
        return VerificationResult(
            success=False,
            errors=["Invalid device proof"]
        )
    
    async def _verify_time_window_proof(self, rule: PolicyRule, 
                                      proof_request: ProofRequest) -> VerificationResult:
        """Verify time window constraint"""
        current_time = datetime.now()
        
        start_time_str = rule.params.get("start")
        end_time_str = rule.params.get("end")
        
        try:
            # Parse time strings (simplified - support various formats in production)
            start_time = datetime.fromisoformat(start_time_str.replace('Z', '+00:00'))
            end_time = datetime.fromisoformat(end_time_str.replace('Z', '+00:00'))
            
            if start_time <= current_time <= end_time:
                return VerificationResult(success=True)
            else:
                return VerificationResult(
                    success=False,
                    errors=[f"Current time {current_time} not in allowed window [{start_time}, {end_time}]"]
                )
        
        except Exception as e:
            return VerificationResult(
                success=False,
                errors=[f"Invalid time window format: {e}"]
            )
    
    async def _verify_geo_proof(self, rule: PolicyRule, 
                              proof_request: ProofRequest) -> VerificationResult:
        """Verify geolocation constraint"""
        geo_proof = proof_request.proofs.get("geo")
        if not geo_proof:
            return VerificationResult(
                success=False,
                errors=["Geolocation proof required"]
            )
        
        required_lat = rule.params.get("lat")
        required_lon = rule.params.get("lon")
        required_radius = rule.params.get("radius")
        
        provided_lat = geo_proof.get("lat")
        provided_lon = geo_proof.get("lon")
        
        if None in [required_lat, required_lon, required_radius, provided_lat, provided_lon]:
            return VerificationResult(
                success=False,
                errors=["Invalid geolocation parameters"]
            )
        
        # Calculate distance (simplified - use proper geospatial calculations in production)
        lat_diff = abs(required_lat - provided_lat)
        lon_diff = abs(required_lon - provided_lon)
        distance = (lat_diff**2 + lon_diff**2)**0.5 * 111000  # Rough conversion to meters
        
        if distance <= required_radius:
            return VerificationResult(success=True)
        else:
            return VerificationResult(
                success=False,
                errors=[f"Location outside allowed radius: {distance}m > {required_radius}m"]
            )
    
    async def _verify_threshold_proof(self, rule: PolicyRule, 
                                    proof_request: ProofRequest) -> VerificationResult:
        """Verify threshold/custodian proof"""
        threshold_proof = proof_request.proofs.get("threshold")
        if not threshold_proof:
            return VerificationResult(
                success=False,
                errors=["Threshold proof required"]
            )
        
        required_threshold = rule.params.get("threshold")
        custodian_approvals = threshold_proof.get("approvals", [])
        
        if len(custodian_approvals) < required_threshold:
            return VerificationResult(
                success=False,
                errors=[f"Need {required_threshold} custodian approvals, got {len(custodian_approvals)}"]
            )
        
        # Verify each custodian approval (simplified)
        for approval in custodian_approvals:
            custodian_id = approval.get("custodian_id")
            signature = approval.get("signature")
            
            if not custodian_id or not signature:
                return VerificationResult(
                    success=False,
                    errors=["Invalid custodian approval format"]
                )
        
        return VerificationResult(success=True)
    
    async def _verify_puzzle_proof(self, rule: PolicyRule, 
                                 proof_request: ProofRequest) -> VerificationResult:
        """Verify dynamic matrix puzzle proof"""
        puzzle_proof_data = proof_request.proofs.get("puzzle")
        if not puzzle_proof_data:
            return VerificationResult(
                success=False,
                errors=["Puzzle proof required"]
            )
        
        try:
            # Parse puzzle proof
            puzzle_proof = PuzzleProof.from_dict(puzzle_proof_data)
            
            # Get puzzle instance for this layer
            difficulty = rule.params.get("difficulty", 128)
            puzzle = self.puzzle_manager.get_puzzle(proof_request.layer_id)
            
            # Generate challenge for verification
            challenge = puzzle.generate_challenge(
                puzzle_proof.client_seed,
                proof_request.layer_id,
                difficulty
            )
            
            # Verify proof
            if puzzle.verify_proof(puzzle_proof, challenge, proof_request.session_nonce):
                return VerificationResult(success=True)
            else:
                return VerificationResult(
                    success=False,
                    errors=["Invalid puzzle solution"]
                )
        
        except Exception as e:
            return VerificationResult(
                success=False,
                errors=[f"Puzzle verification error: {e}"]
            )
    
    async def _verify_hsm_proof(self, rule: PolicyRule, 
                              proof_request: ProofRequest) -> VerificationResult:
        """Verify HSM unseal proof"""
        hsm_proof = proof_request.proofs.get("hsm")
        if not hsm_proof:
            return VerificationResult(
                success=False,
                errors=["HSM proof required"]
            )
        
        required_key_id = rule.params.get("key_id")
        provided_key_id = hsm_proof.get("key_id")
        
        if required_key_id != provided_key_id:
            return VerificationResult(
                success=False,
                errors=["HSM key ID mismatch"]
            )
        
        # Verify HSM signature (simplified)
        signature = hsm_proof.get("signature")
        if signature:
            return VerificationResult(success=True)
        
        return VerificationResult(
            success=False,
            errors=["Invalid HSM proof"]
        )
    
    async def _verify_risk_proof(self, rule: PolicyRule, 
                               proof_request: ProofRequest) -> VerificationResult:
        """Verify risk assessment proof"""
        max_risk = rule.params.get("max_risk", 0.5)
        
        # Calculate risk score based on various factors
        risk_score = self._calculate_risk_score(proof_request)
        
        if risk_score <= max_risk:
            return VerificationResult(success=True)
        else:
            return VerificationResult(
                success=False,
                errors=[f"Risk score {risk_score} exceeds maximum {max_risk}"]
            )
    
    async def _verify_rate_limit_proof(self, rule: PolicyRule, 
                                     proof_request: ProofRequest) -> VerificationResult:
        """Verify rate limiting constraint"""
        max_count = rule.params.get("count", 10)
        window_seconds = rule.params.get("seconds", 60)
        
        client_id = self._get_client_id(proof_request.client_info)
        
        if self.rate_limiter.check_rate_limit(client_id, max_count, window_seconds):
            return VerificationResult(success=True)
        else:
            return VerificationResult(
                success=False,
                errors=[f"Rate limit exceeded: {max_count} requests per {window_seconds} seconds"]
            )
    
    def _generate_release_token(self, package_id: str, layer_id: int, 
                              session_nonce: bytes) -> ReleaseToken:
        """Generate single-use release token"""
        token_id = secrets.token_urlsafe(32)
        current_time = time.time()
        
        token = ReleaseToken(
            token_id=token_id,
            package_id=package_id,
            layer_id=layer_id,
            session_nonce=session_nonce,
            issued_at=current_time,
            expires_at=current_time + self.token_lifetime
        )
        
        self.active_tokens[token_id] = token
        return token
    
    def validate_and_consume_token(self, token_id: str, 
                                 expected_session_nonce: bytes) -> Optional[ReleaseToken]:
        """Validate and consume a release token (single use)"""
        token = self.active_tokens.get(token_id)
        
        if not token:
            return None
        
        # Check expiration
        if time.time() > token.expires_at:
            del self.active_tokens[token_id]
            return None
        
        # Check if already used
        if token.used:
            return None
        
        # Check session nonce
        if not self.crypto.secure_compare(token.session_nonce, expected_session_nonce):
            return None
        
        # Mark as used and remove from active tokens
        token.used = True
        del self.active_tokens[token_id]
        
        self._audit_log("token_consumed", {
            "token_id": token_id,
            "package_id": token.package_id,
            "layer_id": token.layer_id
        })
        
        return token
    
    def _calculate_risk_score(self, proof_request: ProofRequest) -> float:
        """Calculate risk score based on various factors"""
        risk_score = 0.0
        
        # Factor in client info
        client_info = proof_request.client_info
        
        # Unknown client increases risk
        if not client_info.get("device_id"):
            risk_score += 0.2
        
        # New IP address increases risk
        if not client_info.get("known_ip"):
            risk_score += 0.1
        
        # Time of day factor (higher risk during off-hours)
        current_hour = datetime.now().hour
        if current_hour < 6 or current_hour > 22:
            risk_score += 0.1
        
        # Failed attempts factor
        session = self.session_manager.get_session(proof_request.session_nonce)
        if session:
            failed_attempts = session.get("failed_attempts", 0)
            risk_score += min(failed_attempts * 0.1, 0.3)
        
        return min(risk_score, 1.0)
    
    def _get_client_id(self, client_info: Dict[str, Any]) -> str:
        """Generate client ID for rate limiting"""
        device_id = client_info.get("device_id", "unknown")
        ip_address = client_info.get("ip_address", "unknown")
        return f"{device_id}:{ip_address}"
    
    def _audit_log(self, event_type: str, data: Dict[str, Any]):
        """Add entry to audit log"""
        log_entry = {
            "timestamp": time.time(),
            "event_type": event_type,
            "data": data
        }
        self.audit_log.append(log_entry)
        self.logger.info(f"Audit: {event_type} - {data}")
    
    def get_audit_log(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent audit log entries"""
        return self.audit_log[-limit:]
    
    def cleanup_expired_tokens(self):
        """Remove expired tokens"""
        current_time = time.time()
        expired_tokens = [
            token_id for token_id, token in self.active_tokens.items()
            if current_time > token.expires_at
        ]
        
        for token_id in expired_tokens:
            del self.active_tokens[token_id]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get Gate Evaluator statistics"""
        return {
            "active_sessions": len(self.session_manager.sessions),
            "active_tokens": len(self.active_tokens),
            "total_audit_entries": len(self.audit_log),
            "token_lifetime": self.token_lifetime
        }


