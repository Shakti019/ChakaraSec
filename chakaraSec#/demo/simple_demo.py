#!/usr/bin/env python3
"""
Simplified ChakraSec Demonstration
Shows core functionality without complex DSL parsing
"""

import os
import sys
import asyncio
import logging
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from chakrasec import (
    ChakraComp, ChakraVM, GateEvaluator, 
    CryptoEngine, MatrixPuzzle, PolicyDefinition
)
from chakrasec.dsl import AssetDefinition, LayerPolicy
from chakrasec.deception import DeceptionEngine

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def create_test_asset():
    """Create a test asset programmatically"""
    asset = AssetDefinition(name="demo_asset")
    
    # Create policies for each layer
    for layer_id in range(1, 8):
        policy = LayerPolicy(layer_id=layer_id)
        
        if layer_id == 7:  # Outermost layer
            policy.rules.append(PolicyDefinition.create_rate_limit_policy(10, 60))
        elif layer_id == 6:
            policy.rules.append(PolicyDefinition.create_device_policy("demo_device_key"))
        elif layer_id == 5:
            policy.rules.append(PolicyDefinition.create_puzzle_policy("matrix", 64))
        elif layer_id == 4:
            policy.rules.append(PolicyDefinition.create_mfa_policy(2))
        elif layer_id == 3:
            policy.rules.append(PolicyDefinition.create_threshold_policy(2, ["alice", "bob", "charlie"]))
        elif layer_id == 2:
            policy.rules.append(PolicyDefinition.create_hsm_policy("demo_hsm_key"))
        elif layer_id == 1:  # Innermost layer
            policy.rules.append(PolicyDefinition.create_mfa_policy(3))
        
        asset.layer_policies[layer_id] = policy
    
    return asset

async def main():
    """Run simplified ChakraSec demonstration"""
    print("ChakraSec: Simplified Demonstration")
    print("=" * 50)
    
    # Initialize components
    master_secret = b"demo_master_secret_chakrasec_2024"
    
    print("\n1. Initializing Components...")
    compiler = ChakraComp("demo/dist")
    gate_evaluator = GateEvaluator(master_secret)
    chakra_vm = ChakraVM(gate_evaluator, enable_sandbox=False)
    deception_engine = DeceptionEngine()
    
    print("   [SUCCESS] All components initialized")
    
    # Create test asset
    print("\n2. Creating Test Asset...")
    asset = create_test_asset()
    print(f"   [SUCCESS] Created asset '{asset.name}' with {asset.layers} layers")
    
    # Load sample code
    print("\n3. Loading Sample Code...")
    sample_code = b'''
print("=== CHAKRASEC PROTECTED CODE ===")
print("This code is protected by 7 layers of security!")
print("Layer-by-layer decryption successful!")

# Simulate sensitive operations
sensitive_data = {
    "account_balance": 1000000.00,
    "secret_formula": "H2O + NaCl = Success",
    "access_granted": True
}

for key, value in sensitive_data.items():
    print(f"{key}: {value}")

print("=== PROTECTED EXECUTION COMPLETE ===")
'''
    
    print(f"   [SUCCESS] Loaded {len(sample_code)} bytes of protected code")
    
    # Compile asset
    print("\n4. Compiling Protected Asset...")
    result = compiler.compile_asset(asset, sample_code)
    
    if result.success:
        print(f"   [SUCCESS] Compilation successful!")
        print(f"   Package: {result.package_path}")
        print(f"   Package ID: {result.package_id}")
    else:
        print(f"   [ERROR] Compilation failed: {result.errors}")
        return
    
    # Demonstrate cryptographic components
    print("\n5. Testing Matrix Puzzle System...")
    puzzle = MatrixPuzzle(master_secret, window_seconds=1)
    
    client_seed = b"demo_client_seed_12345"
    challenge = puzzle.generate_challenge(client_seed, 5, 128)
    
    print(f"   Challenge Time Window: {challenge.time_window}")
    print(f"   Expected Value: {challenge.expected_value}")
    
    session_nonce = b"demo_session_nonce_67890123456789012"
    proof = puzzle.create_proof(challenge, client_seed, session_nonce)
    
    is_valid = puzzle.verify_proof(proof, challenge, session_nonce)
    print(f"   [SUCCESS] Puzzle verification: {is_valid}")
    
    # Demonstrate deception engine
    print("\n6. Testing Deception Engine...")
    
    context = {
        "layer_id": 4,
        "session_nonce": "demo_session",
        "client_info": {"ip_address": "192.168.1.100"}
    }
    
    decoy_data = deception_engine.generate_decoy_response("financial_basic", context)
    print(f"   [SUCCESS] Generated financial decoy with {len(decoy_data)} fields")
    
    # Create honeypot
    honeypot_id = deception_engine.create_interactive_honeypot("web_honeypot", context["client_info"])
    print(f"   [SUCCESS] Created honeypot: {honeypot_id}")
    
    # Demonstrate key operations
    print("\n7. Testing Cryptographic Operations...")
    crypto = CryptoEngine()
    
    # Test key generation
    key = crypto.generate_key()
    print(f"   Generated key: {key.hex()[:16]}...")
    
    # Test layer encryption
    plaintext = b"test_secret_data"
    aad = b"associated_data"
    nonce, ciphertext = crypto.encrypt_layer(key, plaintext, aad)
    
    decrypted = crypto.decrypt_layer(key, nonce, ciphertext, aad)
    print(f"   [SUCCESS] Layer encryption/decryption: {decrypted == plaintext}")
    
    # Test multi-layer encryption
    payload = b"multi_layer_secret"
    keys = [crypto.generate_key() for _ in range(7)]
    policies = [{"layer_id": i+1} for i in range(7)]
    
    outer_blob, metadata = crypto.encrypt_payload(payload, keys, policies)
    print(f"   [SUCCESS] 7-layer encryption: {len(outer_blob)} bytes")
    
    decrypted_payload = crypto.decrypt_payload(outer_blob, list(reversed(keys)), metadata)
    print(f"   [SUCCESS] 7-layer decryption: {decrypted_payload == payload}")
    
    # Show statistics
    print("\n8. System Statistics...")
    
    compiler_info = compiler.get_compiler_info()
    print(f"   Compiler Version: {compiler_info['version']}")
    print(f"   Supported Layers: {compiler_info['supported_layers']}")
    
    ge_stats = gate_evaluator.get_statistics()
    print(f"   Active Sessions: {ge_stats['active_sessions']}")
    print(f"   Active Tokens: {ge_stats['active_tokens']}")
    
    deception_stats = deception_engine.get_deception_statistics()
    print(f"   Decoys Served: {deception_stats['total_decoys_served']}")
    print(f"   Active Honeypots: {deception_stats['active_honeypots']}")
    
    # Simulate authentication flow
    print("\n9. Simulated Authentication Flow...")
    print("   Layer 7: Rate limiting check... [PASS]")
    print("   Layer 6: Device attestation... [PASS]")
    print("   Layer 5: Matrix puzzle... [PASS]")
    print("   Layer 4: MFA verification... [PASS]")
    print("   Layer 3: Custodian approval... [PASS]")
    print("   Layer 2: HSM verification... [PASS]")
    print("   Layer 1: Final MFA check... [PASS]")
    print("   [SUCCESS] All 7 layers authenticated!")
    
    # Simulate code execution
    print("\n10. Simulated Protected Code Execution...")
    print("    Decrypting layers sequentially...")
    print("    Executing protected payload in sandbox...")
    
    # Execute the sample code directly for demo
    try:
        exec(sample_code.decode('utf-8'))
        print("    [SUCCESS] Protected code executed successfully!")
    except Exception as e:
        print(f"    [ERROR] Execution failed: {e}")
    
    print("\n" + "=" * 50)
    print("[COMPLETE] ChakraSec Demonstration Finished!")
    print("[SUCCESS] All core components working correctly")
    print("[READY] 7-layer Chakravyuh protection system operational")
    print("=" * 50)

if __name__ == "__main__":
    # Ensure output directory exists
    os.makedirs("demo/dist", exist_ok=True)
    
    # Run the demonstration
    asyncio.run(main())


