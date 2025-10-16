"""
ChakraSec: A Multi-Layered Cryptographic Protection System

Inspired by the Abhimanyu Chakravyuh concept from Indian mythology,
this implements a 7-layer concentric cryptographic protection system.
"""

import hashlib
import json
import time
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import secrets


@dataclass
class AccessPolicy:
    """Defines access control policies for a layer"""
    required_role: str
    time_window: Optional[int] = None  # seconds
    max_attempts: int = 3
    requires_sequential: bool = True
    custom_rules: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LayerProof:
    """Proof of successful layer traversal"""
    layer_number: int
    timestamp: float
    user_id: str
    proof_hash: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuditLog:
    """Audit log entry"""
    timestamp: float
    layer: int
    user_id: str
    action: str
    success: bool
    details: Dict[str, Any] = field(default_factory=dict)


class ChakraLayer:
    """Base class for a security layer in the Chakravyuh"""
    
    def __init__(self, layer_number: int, policy: AccessPolicy):
        self.layer_number = layer_number
        self.policy = policy
        self.audit_logs: List[AuditLog] = []
    
    def verify(self, context: Dict[str, Any]) -> bool:
        """Verify if access should be granted based on layer policy"""
        raise NotImplementedError
    
    def log_access(self, user_id: str, action: str, success: bool, details: Dict[str, Any] = None):
        """Log an access attempt"""
        log = AuditLog(
            timestamp=time.time(),
            layer=self.layer_number,
            user_id=user_id,
            action=action,
            success=success,
            details=details or {}
        )
        self.audit_logs.append(log)
        return log


class Layer1_Authentication(ChakraLayer):
    """Layer 1: Authentication & Identity Verification"""
    
    def __init__(self, policy: AccessPolicy):
        super().__init__(1, policy)
        self.user_credentials: Dict[str, str] = {}
    
    def register_user(self, user_id: str, password: str):
        """Register a new user with hashed credentials"""
        salt = secrets.token_bytes(32)
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        self.user_credentials[user_id] = {
            'salt': salt.hex(),
            'hash': password_hash.hex()
        }
    
    def verify(self, context: Dict[str, Any]) -> bool:
        """Verify user credentials"""
        user_id = context.get('user_id')
        password = context.get('password')
        
        if not user_id or not password:
            self.log_access(user_id or 'unknown', 'authenticate', False, {'reason': 'missing_credentials'})
            return False
        
        if user_id not in self.user_credentials:
            self.log_access(user_id, 'authenticate', False, {'reason': 'user_not_found'})
            return False
        
        creds = self.user_credentials[user_id]
        salt = bytes.fromhex(creds['salt'])
        stored_hash = creds['hash']
        
        computed_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000).hex()
        
        success = computed_hash == stored_hash
        self.log_access(user_id, 'authenticate', success)
        return success


class Layer2_TimeBasedAccess(ChakraLayer):
    """Layer 2: Time-bound Access Control"""
    
    def __init__(self, policy: AccessPolicy):
        super().__init__(2, policy)
        self.access_windows: Dict[str, Dict[str, Any]] = {}
    
    def grant_time_window(self, user_id: str, duration_seconds: int):
        """Grant a time-limited access window"""
        self.access_windows[user_id] = {
            'start': time.time(),
            'duration': duration_seconds,
            'expires': time.time() + duration_seconds
        }
    
    def verify(self, context: Dict[str, Any]) -> bool:
        """Verify time-based access"""
        user_id = context.get('user_id')
        current_time = time.time()
        
        if user_id not in self.access_windows:
            self.log_access(user_id, 'time_check', False, {'reason': 'no_time_window'})
            return False
        
        window = self.access_windows[user_id]
        if current_time > window['expires']:
            self.log_access(user_id, 'time_check', False, {'reason': 'window_expired'})
            return False
        
        self.log_access(user_id, 'time_check', True, {'remaining': window['expires'] - current_time})
        return True


class Layer3_KeyManagement(ChakraLayer):
    """Layer 3: Cryptographic Key Management"""
    
    def __init__(self, policy: AccessPolicy):
        super().__init__(3, policy)
        self.user_keys: Dict[str, bytes] = {}
    
    def generate_user_key(self, user_id: str, master_password: str) -> bytes:
        """Generate a cryptographic key for a user"""
        salt = user_id.encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(master_password.encode())
        self.user_keys[user_id] = key
        return key
    
    def verify(self, context: Dict[str, Any]) -> bool:
        """Verify that user has a valid key"""
        user_id = context.get('user_id')
        
        if user_id not in self.user_keys:
            self.log_access(user_id, 'key_check', False, {'reason': 'no_key'})
            return False
        
        self.log_access(user_id, 'key_check', True)
        return True
    
    def get_key(self, user_id: str) -> Optional[bytes]:
        """Retrieve user's cryptographic key"""
        return self.user_keys.get(user_id)


class Layer4_DataEncryption(ChakraLayer):
    """Layer 4: Data Encryption/Decryption"""
    
    def __init__(self, policy: AccessPolicy):
        super().__init__(4, policy)
        self.encrypted_data: Dict[str, bytes] = {}
    
    def encrypt_data(self, data: bytes, key: bytes, data_id: str) -> bytes:
        """Encrypt data using Fernet symmetric encryption"""
        fernet = Fernet(self._derive_fernet_key(key))
        encrypted = fernet.encrypt(data)
        self.encrypted_data[data_id] = encrypted
        return encrypted
    
    def decrypt_data(self, data_id: str, key: bytes) -> Optional[bytes]:
        """Decrypt data"""
        if data_id not in self.encrypted_data:
            return None
        
        try:
            fernet = Fernet(self._derive_fernet_key(key))
            decrypted = fernet.decrypt(self.encrypted_data[data_id])
            return decrypted
        except Exception:
            return None
    
    def _derive_fernet_key(self, key: bytes) -> bytes:
        """Derive a Fernet-compatible key from raw bytes"""
        import base64
        # Ensure key is 32 bytes and base64url encoded
        if len(key) != 32:
            key = hashlib.sha256(key).digest()
        return base64.urlsafe_b64encode(key)
    
    def verify(self, context: Dict[str, Any]) -> bool:
        """Verify encryption capabilities"""
        user_id = context.get('user_id')
        key = context.get('encryption_key')
        
        if not key:
            self.log_access(user_id, 'encryption_check', False, {'reason': 'no_key'})
            return False
        
        self.log_access(user_id, 'encryption_check', True)
        return True


class Layer5_PolicyAuthorization(ChakraLayer):
    """Layer 5: Policy-based Authorization"""
    
    def __init__(self, policy: AccessPolicy):
        super().__init__(5, policy)
        self.user_roles: Dict[str, str] = {}
        self.role_permissions: Dict[str, List[str]] = {
            'admin': ['read', 'write', 'delete', 'manage'],
            'user': ['read', 'write'],
            'guest': ['read']
        }
    
    def assign_role(self, user_id: str, role: str):
        """Assign a role to a user"""
        if role in self.role_permissions:
            self.user_roles[user_id] = role
    
    def verify(self, context: Dict[str, Any]) -> bool:
        """Verify role-based authorization"""
        user_id = context.get('user_id')
        required_permission = context.get('permission', 'read')
        
        if user_id not in self.user_roles:
            self.log_access(user_id, 'authorization', False, {'reason': 'no_role'})
            return False
        
        role = self.user_roles[user_id]
        
        # Check if role meets policy requirement
        if self.policy.required_role and role != self.policy.required_role:
            if not self._role_hierarchy_check(role, self.policy.required_role):
                self.log_access(user_id, 'authorization', False, {'reason': 'insufficient_role'})
                return False
        
        # Check if role has required permission
        permissions = self.role_permissions.get(role, [])
        if required_permission not in permissions:
            self.log_access(user_id, 'authorization', False, {'reason': 'insufficient_permissions'})
            return False
        
        self.log_access(user_id, 'authorization', True, {'role': role, 'permission': required_permission})
        return True
    
    def _role_hierarchy_check(self, user_role: str, required_role: str) -> bool:
        """Check if user role satisfies required role based on hierarchy"""
        hierarchy = {'guest': 0, 'user': 1, 'admin': 2}
        return hierarchy.get(user_role, 0) >= hierarchy.get(required_role, 0)


class Layer6_AuditLogging(ChakraLayer):
    """Layer 6: Audit & Logging"""
    
    def __init__(self, policy: AccessPolicy):
        super().__init__(6, policy)
        self.comprehensive_logs: List[Dict[str, Any]] = []
    
    def record_event(self, event_type: str, user_id: str, details: Dict[str, Any]):
        """Record a comprehensive audit event"""
        event = {
            'timestamp': time.time(),
            'event_type': event_type,
            'user_id': user_id,
            'details': details,
            'hash': self._compute_event_hash(event_type, user_id, details)
        }
        self.comprehensive_logs.append(event)
        return event
    
    def _compute_event_hash(self, event_type: str, user_id: str, details: Dict[str, Any]) -> str:
        """Compute a hash of the event for integrity"""
        event_string = f"{event_type}:{user_id}:{json.dumps(details, sort_keys=True)}"
        return hashlib.sha256(event_string.encode()).hexdigest()
    
    def verify(self, context: Dict[str, Any]) -> bool:
        """Verify audit logging is active"""
        user_id = context.get('user_id')
        
        # Record the verification attempt
        self.record_event('audit_check', user_id, {'status': 'active'})
        self.log_access(user_id, 'audit_check', True)
        return True
    
    def get_user_logs(self, user_id: str) -> List[Dict[str, Any]]:
        """Retrieve all logs for a specific user"""
        return [log for log in self.comprehensive_logs if log['user_id'] == user_id]


class Layer7_SequentialProof(ChakraLayer):
    """Layer 7: Proof of Sequential Access"""
    
    def __init__(self, policy: AccessPolicy):
        super().__init__(7, policy)
        self.proofs: Dict[str, List[LayerProof]] = {}
    
    def record_proof(self, user_id: str, layer_number: int, metadata: Dict[str, Any] = None) -> LayerProof:
        """Record proof of layer traversal"""
        proof = LayerProof(
            layer_number=layer_number,
            timestamp=time.time(),
            user_id=user_id,
            proof_hash=self._compute_proof_hash(user_id, layer_number),
            metadata=metadata or {}
        )
        
        if user_id not in self.proofs:
            self.proofs[user_id] = []
        
        self.proofs[user_id].append(proof)
        return proof
    
    def _compute_proof_hash(self, user_id: str, layer_number: int) -> str:
        """Compute cryptographic proof hash"""
        proof_string = f"{user_id}:{layer_number}:{time.time()}:{secrets.token_hex(16)}"
        return hashlib.sha256(proof_string.encode()).hexdigest()
    
    def verify(self, context: Dict[str, Any]) -> bool:
        """Verify sequential access through previous layers"""
        user_id = context.get('user_id')
        check_all_layers = context.get('check_all_layers', False)
        
        if user_id not in self.proofs:
            self.log_access(user_id, 'sequential_proof', False, {'reason': 'no_proofs'})
            return False
        
        user_proofs = self.proofs[user_id]
        
        # Determine which layers to check
        if check_all_layers:
            # For final verification - check all 7 layers
            required_layers = set(range(1, 8))
        else:
            # For layer 7 traversal - check layers 1-6 only
            layers_traversed = set(proof.layer_number for proof in user_proofs)
            required_layers = set(range(1, 7))
        
        # Verify required layers have been traversed
        layers_traversed = set(proof.layer_number for proof in user_proofs)
        
        if not required_layers.issubset(layers_traversed):
            missing = required_layers - layers_traversed
            self.log_access(user_id, 'sequential_proof', False, {
                'reason': 'incomplete_traversal',
                'missing_layers': list(missing)
            })
            return False
        
        # Verify sequential order (most recent proof for each layer)
        latest_proofs = {}
        for proof in user_proofs:
            if proof.layer_number not in latest_proofs or proof.timestamp > latest_proofs[proof.layer_number].timestamp:
                latest_proofs[proof.layer_number] = proof
        
        sorted_proofs = sorted(latest_proofs.values(), key=lambda p: p.layer_number)
        
        # Check if layers were traversed in order
        for i in range(len(sorted_proofs) - 1):
            if sorted_proofs[i].timestamp > sorted_proofs[i + 1].timestamp:
                self.log_access(user_id, 'sequential_proof', False, {
                    'reason': 'non_sequential_access',
                    'violation': f"Layer {sorted_proofs[i+1].layer_number} accessed before Layer {sorted_proofs[i].layer_number}"
                })
                return False
        
        self.log_access(user_id, 'sequential_proof', True, {
            'layers_traversed': len(layers_traversed),
            'total_proofs': len(user_proofs)
        })
        return True
    
    def get_user_proofs(self, user_id: str) -> List[LayerProof]:
        """Get all proofs for a user"""
        return self.proofs.get(user_id, [])


class ChakraSec:
    """
    Main ChakraSec system implementing the 7-layer Chakravyuh protection.
    
    The seven layers are:
    1. Authentication & Identity Verification
    2. Time-bound Access Control
    3. Cryptographic Key Management
    4. Data Encryption/Decryption
    5. Policy-based Authorization
    6. Audit & Logging
    7. Proof of Sequential Access
    """
    
    def __init__(self):
        # Initialize all 7 layers with default policies
        self.layers: Dict[int, ChakraLayer] = {
            1: Layer1_Authentication(AccessPolicy(required_role='user')),
            2: Layer2_TimeBasedAccess(AccessPolicy(required_role='user', time_window=3600)),
            3: Layer3_KeyManagement(AccessPolicy(required_role='user')),
            4: Layer4_DataEncryption(AccessPolicy(required_role='user')),
            5: Layer5_PolicyAuthorization(AccessPolicy(required_role='user')),
            6: Layer6_AuditLogging(AccessPolicy(required_role='user')),
            7: Layer7_SequentialProof(AccessPolicy(required_role='user', requires_sequential=True))
        }
        
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
    
    def register_user(self, user_id: str, password: str, role: str = 'user'):
        """Register a new user in the system"""
        # Layer 1: Register credentials
        self.layers[1].register_user(user_id, password)
        
        # Layer 5: Assign role
        self.layers[5].assign_role(user_id, role)
        
        # Layer 6: Log registration
        self.layers[6].record_event('user_registration', user_id, {'role': role})
    
    def authenticate_user(self, user_id: str, password: str, master_password: str = None) -> bool:
        """Authenticate a user and initialize session"""
        context = {'user_id': user_id, 'password': password}
        
        # Layer 1: Authenticate
        if not self.layers[1].verify(context):
            return False
        
        # Layer 2: Grant time window (default 1 hour)
        self.layers[2].grant_time_window(user_id, 3600)
        
        # Layer 3: Generate encryption key
        master_pwd = master_password or password
        key = self.layers[3].generate_user_key(user_id, master_pwd)
        
        # Layer 6: Log authentication
        self.layers[6].record_event('user_authentication', user_id, {'success': True})
        
        # Layer 7: Record proof of Layer 1 traversal
        self.layers[7].record_proof(user_id, 1, {'action': 'authentication'})
        
        # Create session
        self.active_sessions[user_id] = {
            'authenticated': True,
            'key': key,
            'start_time': time.time()
        }
        
        return True
    
    def traverse_layer(self, user_id: str, layer_number: int, context: Dict[str, Any] = None) -> bool:
        """Traverse a specific layer"""
        if layer_number not in self.layers:
            return False
        
        context = context or {}
        context['user_id'] = user_id
        
        # Add encryption key to context if available
        if user_id in self.active_sessions:
            context['encryption_key'] = self.active_sessions[user_id].get('key')
        
        # Verify the layer
        layer = self.layers[layer_number]
        if layer.verify(context):
            # Record proof of traversal
            self.layers[7].record_proof(user_id, layer_number, context)
            
            # Log the traversal
            self.layers[6].record_event(f'layer_{layer_number}_traversal', user_id, {
                'success': True,
                'layer': layer_number
            })
            
            return True
        
        return False
    
    def encrypt_asset(self, user_id: str, data: bytes, asset_id: str) -> Optional[bytes]:
        """Encrypt a sensitive asset"""
        if user_id not in self.active_sessions:
            return None
        
        key = self.active_sessions[user_id]['key']
        encrypted = self.layers[4].encrypt_data(data, key, asset_id)
        
        # Log encryption
        self.layers[6].record_event('asset_encryption', user_id, {
            'asset_id': asset_id,
            'size': len(data)
        })
        
        return encrypted
    
    def decrypt_asset(self, user_id: str, asset_id: str) -> Optional[bytes]:
        """Decrypt a sensitive asset (requires sequential layer traversal)"""
        # Verify sequential access through all 7 layers
        if not self.layers[7].verify({'user_id': user_id, 'check_all_layers': True}):
            return None
        
        if user_id not in self.active_sessions:
            return None
        
        key = self.active_sessions[user_id]['key']
        decrypted = self.layers[4].decrypt_data(asset_id, key)
        
        if decrypted:
            # Log decryption
            self.layers[6].record_event('asset_decryption', user_id, {
                'asset_id': asset_id,
                'success': True
            })
        
        return decrypted
    
    def get_audit_trail(self, user_id: str) -> Dict[str, Any]:
        """Get comprehensive audit trail for a user"""
        return {
            'user_id': user_id,
            'comprehensive_logs': self.layers[6].get_user_logs(user_id),
            'layer_proofs': self.layers[7].get_user_proofs(user_id),
            'layer_logs': {
                layer_num: layer.audit_logs
                for layer_num, layer in self.layers.items()
            }
        }
    
    def verify_full_access(self, user_id: str) -> bool:
        """Verify that user has successfully traversed all 7 layers"""
        return self.layers[7].verify({'user_id': user_id, 'check_all_layers': True})
