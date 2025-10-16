"""
Comprehensive tests for ChakraSec multi-layered protection system
"""

import unittest
import time
from chakrasec import (
    ChakraSec,
    Layer1_Authentication,
    Layer2_TimeBasedAccess,
    Layer3_KeyManagement,
    Layer4_DataEncryption,
    Layer5_PolicyAuthorization,
    Layer6_AuditLogging,
    Layer7_SequentialProof,
    AccessPolicy
)


class TestLayer1Authentication(unittest.TestCase):
    """Test Layer 1: Authentication & Identity Verification"""
    
    def setUp(self):
        self.layer = Layer1_Authentication(AccessPolicy(required_role='user'))
    
    def test_user_registration(self):
        """Test user registration with password hashing"""
        self.layer.register_user('test_user', 'secure_password')
        self.assertIn('test_user', self.layer.user_credentials)
        self.assertIn('salt', self.layer.user_credentials['test_user'])
        self.assertIn('hash', self.layer.user_credentials['test_user'])
    
    def test_successful_authentication(self):
        """Test successful user authentication"""
        self.layer.register_user('test_user', 'secure_password')
        context = {'user_id': 'test_user', 'password': 'secure_password'}
        self.assertTrue(self.layer.verify(context))
    
    def test_failed_authentication_wrong_password(self):
        """Test failed authentication with wrong password"""
        self.layer.register_user('test_user', 'secure_password')
        context = {'user_id': 'test_user', 'password': 'wrong_password'}
        self.assertFalse(self.layer.verify(context))
    
    def test_failed_authentication_unknown_user(self):
        """Test failed authentication for unknown user"""
        context = {'user_id': 'unknown_user', 'password': 'any_password'}
        self.assertFalse(self.layer.verify(context))
    
    def test_failed_authentication_missing_credentials(self):
        """Test failed authentication with missing credentials"""
        context = {'user_id': 'test_user'}
        self.assertFalse(self.layer.verify(context))


class TestLayer2TimeBasedAccess(unittest.TestCase):
    """Test Layer 2: Time-bound Access Control"""
    
    def setUp(self):
        self.layer = Layer2_TimeBasedAccess(AccessPolicy(required_role='user'))
    
    def test_time_window_grant(self):
        """Test granting a time window"""
        self.layer.grant_time_window('test_user', 60)
        self.assertIn('test_user', self.layer.access_windows)
        self.assertIn('expires', self.layer.access_windows['test_user'])
    
    def test_valid_time_window(self):
        """Test access within valid time window"""
        self.layer.grant_time_window('test_user', 60)
        context = {'user_id': 'test_user'}
        self.assertTrue(self.layer.verify(context))
    
    def test_expired_time_window(self):
        """Test access after time window expires"""
        self.layer.grant_time_window('test_user', 1)
        time.sleep(2)
        context = {'user_id': 'test_user'}
        self.assertFalse(self.layer.verify(context))
    
    def test_no_time_window(self):
        """Test access without granted time window"""
        context = {'user_id': 'test_user'}
        self.assertFalse(self.layer.verify(context))


class TestLayer3KeyManagement(unittest.TestCase):
    """Test Layer 3: Cryptographic Key Management"""
    
    def setUp(self):
        self.layer = Layer3_KeyManagement(AccessPolicy(required_role='user'))
    
    def test_key_generation(self):
        """Test cryptographic key generation"""
        key = self.layer.generate_user_key('test_user', 'master_password')
        self.assertIsNotNone(key)
        self.assertEqual(len(key), 32)  # 256-bit key
    
    def test_key_verification(self):
        """Test key verification"""
        self.layer.generate_user_key('test_user', 'master_password')
        context = {'user_id': 'test_user'}
        self.assertTrue(self.layer.verify(context))
    
    def test_no_key(self):
        """Test verification without key"""
        context = {'user_id': 'test_user'}
        self.assertFalse(self.layer.verify(context))
    
    def test_key_retrieval(self):
        """Test key retrieval"""
        key = self.layer.generate_user_key('test_user', 'master_password')
        retrieved = self.layer.get_key('test_user')
        self.assertEqual(key, retrieved)


class TestLayer4DataEncryption(unittest.TestCase):
    """Test Layer 4: Data Encryption/Decryption"""
    
    def setUp(self):
        self.layer = Layer4_DataEncryption(AccessPolicy(required_role='user'))
    
    def test_encryption(self):
        """Test data encryption"""
        data = b"Sensitive information"
        key = b"0" * 32  # 256-bit key
        encrypted = self.layer.encrypt_data(data, key, 'asset1')
        self.assertNotEqual(data, encrypted)
        self.assertIn('asset1', self.layer.encrypted_data)
    
    def test_decryption(self):
        """Test data decryption"""
        data = b"Sensitive information"
        key = b"0" * 32
        self.layer.encrypt_data(data, key, 'asset1')
        decrypted = self.layer.decrypt_data('asset1', key)
        self.assertEqual(data, decrypted)
    
    def test_decryption_wrong_key(self):
        """Test decryption with wrong key"""
        data = b"Sensitive information"
        key1 = b"0" * 32
        key2 = b"1" * 32
        self.layer.encrypt_data(data, key1, 'asset1')
        decrypted = self.layer.decrypt_data('asset1', key2)
        self.assertIsNone(decrypted)
    
    def test_decryption_nonexistent_asset(self):
        """Test decryption of nonexistent asset"""
        key = b"0" * 32
        decrypted = self.layer.decrypt_data('nonexistent', key)
        self.assertIsNone(decrypted)


class TestLayer5PolicyAuthorization(unittest.TestCase):
    """Test Layer 5: Policy-based Authorization"""
    
    def setUp(self):
        self.layer = Layer5_PolicyAuthorization(AccessPolicy(required_role='user'))
    
    def test_role_assignment(self):
        """Test role assignment"""
        self.layer.assign_role('test_user', 'admin')
        self.assertEqual(self.layer.user_roles['test_user'], 'admin')
    
    def test_admin_permissions(self):
        """Test admin role permissions"""
        self.layer.assign_role('test_user', 'admin')
        context = {'user_id': 'test_user', 'permission': 'delete'}
        self.assertTrue(self.layer.verify(context))
    
    def test_user_permissions(self):
        """Test user role permissions"""
        self.layer.assign_role('test_user', 'user')
        context = {'user_id': 'test_user', 'permission': 'write'}
        self.assertTrue(self.layer.verify(context))
    
    def test_insufficient_permissions(self):
        """Test insufficient permissions"""
        self.layer.assign_role('test_user', 'guest')
        context = {'user_id': 'test_user', 'permission': 'write'}
        self.assertFalse(self.layer.verify(context))
    
    def test_no_role(self):
        """Test authorization without role"""
        context = {'user_id': 'test_user', 'permission': 'read'}
        self.assertFalse(self.layer.verify(context))


class TestLayer6AuditLogging(unittest.TestCase):
    """Test Layer 6: Audit & Logging"""
    
    def setUp(self):
        self.layer = Layer6_AuditLogging(AccessPolicy(required_role='user'))
    
    def test_event_recording(self):
        """Test event recording"""
        event = self.layer.record_event('login', 'test_user', {'ip': '127.0.0.1'})
        self.assertIn('timestamp', event)
        self.assertIn('hash', event)
        self.assertEqual(event['event_type'], 'login')
    
    def test_get_user_logs(self):
        """Test retrieving user logs"""
        self.layer.record_event('login', 'user1', {})
        self.layer.record_event('logout', 'user2', {})
        self.layer.record_event('access', 'user1', {})
        
        user1_logs = self.layer.get_user_logs('user1')
        self.assertEqual(len(user1_logs), 2)
    
    def test_audit_verification(self):
        """Test audit verification"""
        context = {'user_id': 'test_user'}
        self.assertTrue(self.layer.verify(context))
        # Should have logged the verification
        self.assertGreater(len(self.layer.comprehensive_logs), 0)


class TestLayer7SequentialProof(unittest.TestCase):
    """Test Layer 7: Proof of Sequential Access"""
    
    def setUp(self):
        self.layer = Layer7_SequentialProof(AccessPolicy(required_role='user', requires_sequential=True))
    
    def test_proof_recording(self):
        """Test proof recording"""
        proof = self.layer.record_proof('test_user', 1, {'action': 'test'})
        self.assertEqual(proof.layer_number, 1)
        self.assertEqual(proof.user_id, 'test_user')
        self.assertIn('test_user', self.layer.proofs)
    
    def test_sequential_access_success(self):
        """Test successful sequential access verification"""
        # Record proofs for all 7 layers in order
        for layer_num in range(1, 8):
            self.layer.record_proof('test_user', layer_num)
            time.sleep(0.01)  # Small delay to ensure different timestamps
        
        context = {'user_id': 'test_user'}
        self.assertTrue(self.layer.verify(context))
    
    def test_incomplete_traversal(self):
        """Test verification with incomplete layer traversal"""
        # Only traverse first 5 layers
        for layer_num in range(1, 6):
            self.layer.record_proof('test_user', layer_num)
        
        context = {'user_id': 'test_user'}
        self.assertFalse(self.layer.verify(context))
    
    def test_no_proofs(self):
        """Test verification without any proofs"""
        context = {'user_id': 'test_user'}
        self.assertFalse(self.layer.verify(context))
    
    def test_get_user_proofs(self):
        """Test retrieving user proofs"""
        self.layer.record_proof('test_user', 1)
        self.layer.record_proof('test_user', 2)
        
        proofs = self.layer.get_user_proofs('test_user')
        self.assertEqual(len(proofs), 2)


class TestChakraSec(unittest.TestCase):
    """Test the complete ChakraSec system"""
    
    def setUp(self):
        self.chakra = ChakraSec()
    
    def test_user_registration(self):
        """Test complete user registration"""
        self.chakra.register_user('test_user', 'password123', 'user')
        self.assertIn('test_user', self.chakra.layers[1].user_credentials)
        self.assertIn('test_user', self.chakra.layers[5].user_roles)
    
    def test_user_authentication(self):
        """Test user authentication flow"""
        self.chakra.register_user('test_user', 'password123')
        success = self.chakra.authenticate_user('test_user', 'password123')
        self.assertTrue(success)
        self.assertIn('test_user', self.chakra.active_sessions)
    
    def test_layer_traversal(self):
        """Test layer-by-layer traversal"""
        self.chakra.register_user('test_user', 'password123')
        self.chakra.authenticate_user('test_user', 'password123')
        
        # Traverse remaining layers
        for layer_num in range(2, 8):
            success = self.chakra.traverse_layer('test_user', layer_num)
            self.assertTrue(success, f"Failed to traverse layer {layer_num}")
    
    def test_asset_encryption(self):
        """Test asset encryption"""
        self.chakra.register_user('test_user', 'password123')
        self.chakra.authenticate_user('test_user', 'password123')
        
        data = b"Top secret information"
        encrypted = self.chakra.encrypt_asset('test_user', data, 'secret1')
        self.assertIsNotNone(encrypted)
        self.assertNotEqual(data, encrypted)
    
    def test_asset_decryption_with_sequential_access(self):
        """Test asset decryption requiring sequential layer access"""
        self.chakra.register_user('test_user', 'password123')
        self.chakra.authenticate_user('test_user', 'password123')
        
        # Encrypt asset
        data = b"Top secret information"
        self.chakra.encrypt_asset('test_user', data, 'secret1')
        
        # Traverse all remaining layers
        for layer_num in range(2, 8):
            self.chakra.traverse_layer('test_user', layer_num)
            time.sleep(0.01)
        
        # Now decrypt should work
        decrypted = self.chakra.decrypt_asset('test_user', 'secret1')
        self.assertIsNotNone(decrypted)
        self.assertEqual(data, decrypted)
    
    def test_asset_decryption_without_sequential_access(self):
        """Test that decryption fails without sequential layer access"""
        self.chakra.register_user('test_user', 'password123')
        self.chakra.authenticate_user('test_user', 'password123')
        
        # Encrypt asset
        data = b"Top secret information"
        self.chakra.encrypt_asset('test_user', data, 'secret1')
        
        # Try to decrypt without traversing all layers
        decrypted = self.chakra.decrypt_asset('test_user', 'secret1')
        self.assertIsNone(decrypted)
    
    def test_full_access_verification(self):
        """Test full access verification through all layers"""
        self.chakra.register_user('test_user', 'password123')
        self.chakra.authenticate_user('test_user', 'password123')
        
        # Should fail before traversing all layers
        self.assertFalse(self.chakra.verify_full_access('test_user'))
        
        # Traverse all remaining layers
        for layer_num in range(2, 8):
            self.chakra.traverse_layer('test_user', layer_num)
            time.sleep(0.01)
        
        # Should succeed after traversing all layers
        self.assertTrue(self.chakra.verify_full_access('test_user'))
    
    def test_audit_trail(self):
        """Test audit trail generation"""
        self.chakra.register_user('test_user', 'password123')
        self.chakra.authenticate_user('test_user', 'password123')
        
        audit = self.chakra.get_audit_trail('test_user')
        self.assertIn('user_id', audit)
        self.assertIn('comprehensive_logs', audit)
        self.assertIn('layer_proofs', audit)
        self.assertGreater(len(audit['comprehensive_logs']), 0)
    
    def test_multi_user_isolation(self):
        """Test that multiple users are properly isolated"""
        self.chakra.register_user('user1', 'pass1')
        self.chakra.register_user('user2', 'pass2')
        
        self.chakra.authenticate_user('user1', 'pass1')
        self.chakra.authenticate_user('user2', 'pass2')
        
        # Encrypt different data for each user
        data1 = b"User 1 secret"
        data2 = b"User 2 secret"
        
        self.chakra.encrypt_asset('user1', data1, 'secret1')
        self.chakra.encrypt_asset('user2', data2, 'secret2')
        
        # Traverse all layers for user1
        for layer_num in range(2, 8):
            self.chakra.traverse_layer('user1', layer_num)
            time.sleep(0.01)
        
        # User1 should only decrypt their own data
        decrypted1 = self.chakra.decrypt_asset('user1', 'secret1')
        self.assertEqual(data1, decrypted1)
        
        # User2's data should not be accessible by user1's key
        # (This is implicit - each user has their own key)


class TestIntegration(unittest.TestCase):
    """Integration tests for complete workflows"""
    
    def test_complete_chakravyuh_flow(self):
        """Test complete Chakravyuh traversal workflow"""
        chakra = ChakraSec()
        
        # Step 1: Register user
        chakra.register_user('alice', 'alice_password', 'admin')
        
        # Step 2: Authenticate
        self.assertTrue(chakra.authenticate_user('alice', 'alice_password'))
        
        # Step 3: Encrypt sensitive asset
        secret_data = b"Classified Information - Access Restricted"
        encrypted = chakra.encrypt_asset('alice', secret_data, 'top_secret_1')
        self.assertIsNotNone(encrypted)
        
        # Step 4: Attempt to decrypt without full traversal (should fail)
        result = chakra.decrypt_asset('alice', 'top_secret_1')
        self.assertIsNone(result)
        
        # Step 5: Traverse remaining layers in sequence
        for layer in range(2, 8):
            success = chakra.traverse_layer('alice', layer)
            self.assertTrue(success, f"Failed at layer {layer}")
            time.sleep(0.01)
        
        # Step 6: Verify full access
        self.assertTrue(chakra.verify_full_access('alice'))
        
        # Step 7: Now decrypt should succeed
        decrypted = chakra.decrypt_asset('alice', 'top_secret_1')
        self.assertIsNotNone(decrypted)
        self.assertEqual(secret_data, decrypted)
        
        # Step 8: Verify audit trail
        audit = chakra.get_audit_trail('alice')
        self.assertGreater(len(audit['comprehensive_logs']), 0)
        self.assertEqual(len(audit['layer_proofs']), 7)  # All 7 layers


if __name__ == '__main__':
    unittest.main()
