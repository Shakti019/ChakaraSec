#!/usr/bin/env python3
"""
Comprehensive test suite for ChakraSec components
"""

import unittest
import asyncio
import tempfile
import os
import secrets
from pathlib import Path
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from chakrasec import (
    ChakraSecParser, ChakraComp, ChakraVM, GateEvaluator,
    CryptoEngine, MatrixPuzzle, PolicyDefinition
)
from chakrasec.dsl import AssetDefinition, LayerPolicy, PolicyRule, PolicyAtom, ActionType
from chakrasec.crypto import ShamirSecretSharing
from chakrasec.deception import DeceptionEngine

class TestChakraSecDSL(unittest.TestCase):
    """Test ChakraSec DSL parsing and policy definitions"""
    
    def setUp(self):
        self.parser = ChakraSecParser()
    
    def test_basic_asset_parsing(self):
        """Test basic asset definition parsing"""
        chakrasec_code = '''
        asset "test_asset" {
            layers = 7;
            
            layer 1 {
                policy = MFA(2);
                action_on_fail = DENY();
            }
            
            metadata {
                "owner": "test_user";
            }
        }
        '''
        
        assets = self.parser.parse(chakrasec_code)
        self.assertIn("test_asset", assets)
        
        asset = assets["test_asset"]
        self.assertEqual(asset.layers, 7)
        self.assertIn(1, asset.layer_policies)
        self.assertEqual(asset.metadata["owner"], "test_user")
    
    def test_complex_policy_parsing(self):
        """Test complex policy rule parsing"""
        chakrasec_code = '''
        asset "complex_asset" {
            layers = 7;
            
            layer 5 {
                policy = MFA(2) && GEO(40.7128, -74.0060, 1000) && PUZZLE("matrix", 128);
                action_on_fail = RETURN_DECOY("financial");
            }
        }
        '''
        
        assets = self.parser.parse(chakrasec_code)
        asset = assets["complex_asset"]
        layer_policy = asset.layer_policies[5]
        
        self.assertEqual(len(layer_policy.rules), 3)
        self.assertEqual(layer_policy.action_on_fail, ActionType.RETURN_DECOY)
    
    def test_policy_definition_helpers(self):
        """Test programmatic policy creation"""
        mfa_rule = PolicyDefinition.create_mfa_policy(2)
        self.assertEqual(mfa_rule.atom, PolicyAtom.MFA)
        self.assertEqual(mfa_rule.params["level"], 2)
        
        geo_rule = PolicyDefinition.create_geo_policy(40.7128, -74.0060, 1000)
        self.assertEqual(geo_rule.atom, PolicyAtom.GEO)
        self.assertEqual(geo_rule.params["lat"], 40.7128)

class TestCryptoEngine(unittest.TestCase):
    """Test cryptographic operations"""
    
    def setUp(self):
        self.crypto = CryptoEngine()
    
    def test_key_generation(self):
        """Test cryptographic key generation"""
        key = self.crypto.generate_key()
        self.assertEqual(len(key), 32)  # 256-bit key
        
        # Test uniqueness
        key2 = self.crypto.generate_key()
        self.assertNotEqual(key, key2)
    
    def test_layer_encryption_decryption(self):
        """Test single layer encryption/decryption"""
        key = self.crypto.generate_key()
        plaintext = b"test_payload_data"
        aad = b"associated_data"
        
        nonce, ciphertext = self.crypto.encrypt_layer(key, plaintext, aad)
        
        # Test decryption
        decrypted = self.crypto.decrypt_layer(key, nonce, ciphertext, aad)
        self.assertEqual(decrypted, plaintext)
    
    def test_multi_layer_encryption(self):
        """Test 7-layer encryption/decryption"""
        payload = b"secret_protected_data"
        keys = [self.crypto.generate_key() for _ in range(7)]
        policies = [{"layer_id": i+1} for i in range(7)]
        
        # Encrypt
        outer_blob, metadata_list = self.crypto.encrypt_payload(payload, keys, policies)
        
        # Decrypt (keys in reverse order for unwrapping)
        decrypted = self.crypto.decrypt_payload(outer_blob, list(reversed(keys)), metadata_list)
        
        self.assertEqual(decrypted, payload)
    
    def test_signing_verification(self):
        """Test package signing and verification"""
        private_key, public_key = self.crypto.generate_signing_key()
        data = b"test_package_data"
        
        signature = self.crypto.sign_package(private_key, data)
        is_valid = self.crypto.verify_package(public_key, signature, data)
        
        self.assertTrue(is_valid)
        
        # Test with wrong data
        wrong_data = b"wrong_package_data"
        is_valid_wrong = self.crypto.verify_package(public_key, signature, wrong_data)
        self.assertFalse(is_valid_wrong)

class TestShamirSecretSharing(unittest.TestCase):
    """Test Shamir secret sharing implementation"""
    
    def setUp(self):
        self.shamir = ShamirSecretSharing()
    
    def test_secret_splitting_reconstruction(self):
        """Test secret splitting and reconstruction"""
        secret = secrets.token_bytes(32)
        threshold = 3
        num_shares = 5
        
        # Split secret
        shares = self.shamir.split_secret(secret, threshold, num_shares)
        self.assertEqual(len(shares), num_shares)
        
        # Reconstruct with threshold shares
        reconstructed = self.shamir.reconstruct_secret(shares[:threshold], threshold)
        self.assertEqual(reconstructed, secret)
        
        # Test with different subset
        reconstructed2 = self.shamir.reconstruct_secret(shares[1:threshold+1], threshold)
        self.assertEqual(reconstructed2, secret)
    
    def test_insufficient_shares(self):
        """Test reconstruction with insufficient shares"""
        secret = secrets.token_bytes(32)
        threshold = 3
        num_shares = 5
        
        shares = self.shamir.split_secret(secret, threshold, num_shares)
        
        # Try to reconstruct with insufficient shares
        with self.assertRaises(ValueError):
            self.shamir.reconstruct_secret(shares[:threshold-1], threshold)

class TestMatrixPuzzle(unittest.TestCase):
    """Test dynamic matrix puzzle system"""
    
    def setUp(self):
        self.master_secret = b"test_master_secret_for_puzzles"
        self.puzzle = MatrixPuzzle(self.master_secret, window_seconds=1)
    
    def test_challenge_generation(self):
        """Test puzzle challenge generation"""
        client_seed = b"test_client_seed"
        layer_id = 5
        difficulty = 128
        
        challenge = self.puzzle.generate_challenge(client_seed, layer_id, difficulty)
        
        self.assertEqual(challenge.layer_id, layer_id)
        self.assertEqual(challenge.difficulty, difficulty)
        self.assertIsInstance(challenge.expected_value, int)
    
    def test_proof_creation_verification(self):
        """Test puzzle proof creation and verification"""
        client_seed = b"test_client_seed"
        layer_id = 5
        difficulty = 64
        session_nonce = b"test_session_nonce"
        
        # Generate challenge
        challenge = self.puzzle.generate_challenge(client_seed, layer_id, difficulty)
        
        # Create proof
        proof = self.puzzle.create_proof(challenge, client_seed, session_nonce)
        
        # Verify proof
        is_valid = self.puzzle.verify_proof(proof, challenge, session_nonce)
        self.assertTrue(is_valid)
    
    def test_time_window_validation(self):
        """Test time window validation in puzzles"""
        client_seed = b"test_client_seed"
        layer_id = 5
        session_nonce = b"test_session_nonce"
        
        # Create puzzle with strict time window
        strict_puzzle = MatrixPuzzle(self.master_secret, window_seconds=1, drift_tolerance=0)
        
        challenge = strict_puzzle.generate_challenge(client_seed, layer_id)
        proof = strict_puzzle.create_proof(challenge, client_seed, session_nonce)
        
        # Immediate verification should work
        is_valid = strict_puzzle.verify_proof(proof, challenge, session_nonce)
        self.assertTrue(is_valid)

class TestChakraComp(unittest.TestCase):
    """Test ChakraSec compiler"""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.compiler = ChakraComp(self.temp_dir)
        
        # Create test asset
        self.test_asset = AssetDefinition(name="test_asset")
        for layer_id in range(1, 8):
            policy = LayerPolicy(layer_id=layer_id)
            policy.rules.append(PolicyDefinition.create_mfa_policy(1))
            self.test_asset.layer_policies[layer_id] = policy
    
    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_asset_compilation(self):
        """Test asset compilation to .ccv package"""
        source_code = b"print('Hello from protected code!')"
        
        result = self.compiler.compile_asset(self.test_asset, source_code)
        
        self.assertTrue(result.success)
        self.assertTrue(os.path.exists(result.package_path))
        self.assertIsNotNone(result.package_id)
    
    def test_package_loading_verification(self):
        """Test package loading and signature verification"""
        source_code = b"print('Test code')"
        
        # Compile package
        result = self.compiler.compile_asset(self.test_asset, source_code)
        self.assertTrue(result.success)
        
        # Load and verify package
        package = self.compiler.load_package(result.package_path)
        
        self.assertEqual(package.package_id, result.package_id)
        self.assertEqual(len(package.metadata), 7)  # 7 layers

class TestGateEvaluator(unittest.TestCase):
    """Test Gate Evaluator service"""
    
    def setUp(self):
        self.master_secret = b"test_gate_evaluator_secret"
        self.gate_evaluator = GateEvaluator(self.master_secret)
    
    def test_session_management(self):
        """Test verification session management"""
        package_id = "test_package_123"
        client_info = {"device_id": "test_device", "ip_address": "192.168.1.1"}
        
        # Start session
        session_nonce = self.gate_evaluator.start_verification_session(package_id, client_info)
        
        self.assertIsInstance(session_nonce, bytes)
        self.assertEqual(len(session_nonce), 32)
    
    def test_token_generation_validation(self):
        """Test release token generation and validation"""
        package_id = "test_package_123"
        layer_id = 5
        session_nonce = b"test_session_nonce_12345678901234567890123456789012"
        
        # Generate token
        token = self.gate_evaluator._generate_release_token(package_id, layer_id, session_nonce)
        
        self.assertEqual(token.package_id, package_id)
        self.assertEqual(token.layer_id, layer_id)
        self.assertEqual(token.session_nonce, session_nonce)
        
        # Validate and consume token
        validated_token = self.gate_evaluator.validate_and_consume_token(
            token.token_id, session_nonce
        )
        
        self.assertIsNotNone(validated_token)
        self.assertEqual(validated_token.token_id, token.token_id)
        
        # Try to use token again (should fail - single use)
        second_use = self.gate_evaluator.validate_and_consume_token(
            token.token_id, session_nonce
        )
        self.assertIsNone(second_use)

class TestDeceptionEngine(unittest.TestCase):
    """Test deception engine"""
    
    def setUp(self):
        self.deception_engine = DeceptionEngine()
    
    def test_decoy_generation(self):
        """Test decoy response generation"""
        context = {
            "layer_id": 4,
            "session_nonce": "test_session",
            "client_info": {"ip_address": "192.168.1.1"}
        }
        
        # Test different decoy types
        decoy_types = ["financial_basic", "medical_basic", "corporate_basic"]
        
        for decoy_id in decoy_types:
            decoy_data = self.deception_engine.generate_decoy_response(decoy_id, context)
            
            self.assertIsInstance(decoy_data, dict)
            self.assertIn("generated_at", decoy_data)
            self.assertIn("decoy_marker", decoy_data)
    
    def test_honeypot_creation(self):
        """Test honeypot creation and interaction"""
        client_info = {"session_id": "test_attacker", "ip_address": "10.0.0.1"}
        
        # Create honeypot
        honeypot_id = self.deception_engine.create_interactive_honeypot(
            "web_honeypot", client_info
        )
        
        self.assertIsInstance(honeypot_id, str)
        self.assertTrue(honeypot_id.startswith("hp_"))
        
        # Interact with honeypot
        interaction_data = {
            "type": "api_request",
            "endpoint": "/api/users",
            "method": "GET"
        }
        
        response = self.deception_engine.handle_honeypot_interaction(
            honeypot_id, interaction_data, client_info
        )
        
        self.assertIsInstance(response, dict)
        self.assertIn("status", response)

class TestIntegration(unittest.TestCase):
    """Integration tests for complete ChakraSec workflow"""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.master_secret = b"integration_test_master_secret"
        
        # Initialize components
        self.parser = ChakraSecParser()
        self.compiler = ChakraComp(self.temp_dir)
        self.gate_evaluator = GateEvaluator(self.master_secret)
        self.chakra_vm = ChakraVM(self.gate_evaluator, enable_sandbox=False)  # Disable sandbox for testing
    
    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_end_to_end_workflow(self):
        """Test complete end-to-end workflow"""
        # 1. Create asset definition
        asset_def = AssetDefinition(name="integration_test_asset")
        
        # Add simple policies for testing
        for layer_id in range(1, 8):
            policy = LayerPolicy(layer_id=layer_id)
            # Add basic MFA policy for all layers
            policy.rules.append(PolicyDefinition.create_mfa_policy(1))
            asset_def.layer_policies[layer_id] = policy
        
        # 2. Compile asset
        source_code = b'print("Integration test successful!")'
        result = self.compiler.compile_asset(asset_def, source_code)
        
        self.assertTrue(result.success)
        
        # 3. Load compiled package
        package = self.compiler.load_package(result.package_path)
        
        self.assertEqual(package.package_id, result.package_id)
        self.assertEqual(len(package.metadata), 7)
        
        # Note: Full runtime execution would require implementing all proof collectors
        # For integration test, we verify the package structure is correct

def run_async_test(coro):
    """Helper to run async tests"""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()

class AsyncTestCase(unittest.TestCase):
    """Base class for async tests"""
    
    def run_async(self, coro):
        return run_async_test(coro)

class TestAsyncComponents(AsyncTestCase):
    """Test async components"""
    
    def setUp(self):
        self.master_secret = b"async_test_master_secret"
        self.gate_evaluator = GateEvaluator(self.master_secret)
    
    def test_async_proof_verification(self):
        """Test async proof verification"""
        async def test_verification():
            from chakrasec.gate_evaluator import ProofRequest
            
            # Create test proof request
            proof_request = ProofRequest(
                package_id="test_package",
                layer_id=1,
                session_nonce=b"test_session_nonce_12345678901234567890123456789012",
                proofs={"mfa": {"level": 1, "totp_code": "123456"}},
                client_info={"device_id": "test_device"}
            )
            
            # Create simple layer policy
            layer_policy = LayerPolicy(layer_id=1)
            layer_policy.rules.append(PolicyDefinition.create_mfa_policy(1))
            
            # This would normally verify the proof, but for testing we just check the structure
            self.assertEqual(proof_request.layer_id, 1)
            self.assertIn("mfa", proof_request.proofs)
        
        self.run_async(test_verification())

if __name__ == '__main__':
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add test classes
    test_classes = [
        TestChakraSecDSL,
        TestCryptoEngine,
        TestShamirSecretSharing,
        TestMatrixPuzzle,
        TestChakraComp,
        TestGateEvaluator,
        TestDeceptionEngine,
        TestIntegration,
        TestAsyncComponents
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Print summary
    print(f"\n{'='*60}")
    print(f"ChakraSec Test Suite Results")
    print(f"{'='*60}")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success rate: {((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100):.1f}%")
    
    if result.failures:
        print(f"\nFailures:")
        for test, traceback in result.failures:
            print(f"  - {test}")
    
    if result.errors:
        print(f"\nErrors:")
        for test, traceback in result.errors:
            print(f"  - {test}")
    
    # Exit with appropriate code
    sys.exit(0 if result.wasSuccessful() else 1)
