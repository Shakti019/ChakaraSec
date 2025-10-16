"""
Example usage of ChakraSec - Multi-Layered Cryptographic Protection System

This example demonstrates how to use the ChakraSec system to protect
sensitive assets through a 7-layer Chakravyuh-inspired security model.
"""

from chakrasec import ChakraSec
import time


def main():
    print("=" * 80)
    print("ChakraSec: Multi-Layered Cryptographic Protection System")
    print("Inspired by the Abhimanyu Chakravyuh from Indian Mythology")
    print("=" * 80)
    print()
    
    # Initialize ChakraSec
    chakra = ChakraSec()
    
    # Step 1: Register a user
    print("Step 1: Registering user 'alice' with admin role...")
    chakra.register_user('alice', 'secure_password_123', 'admin')
    print("✓ User registered successfully")
    print()
    
    # Step 2: Authenticate the user
    print("Step 2: Authenticating user...")
    if chakra.authenticate_user('alice', 'secure_password_123', master_password='master_key_123'):
        print("✓ Authentication successful - Layer 1 traversed")
        print("  - Time-bound access granted (1 hour)")
        print("  - Cryptographic key generated")
    else:
        print("✗ Authentication failed")
        return
    print()
    
    # Step 3: Encrypt a sensitive asset
    print("Step 3: Encrypting sensitive asset...")
    secret_message = b"Top Secret: Launch codes are Alpha-Bravo-Charlie-123"
    encrypted = chakra.encrypt_asset('alice', secret_message, 'mission_critical_1')
    if encrypted:
        print("✓ Asset encrypted successfully")
        print(f"  - Original size: {len(secret_message)} bytes")
        print(f"  - Encrypted size: {len(encrypted)} bytes")
    print()
    
    # Step 4: Attempt to decrypt without full traversal
    print("Step 4: Attempting to decrypt without completing all layers...")
    result = chakra.decrypt_asset('alice', 'mission_critical_1')
    if result is None:
        print("✗ Decryption failed - Sequential layer traversal not complete")
        print("  - Missing layers: 2, 3, 4, 5, 6, 7")
    print()
    
    # Step 5: Traverse remaining layers sequentially
    print("Step 5: Traversing remaining security layers...")
    layer_names = {
        2: "Time-bound Access Control",
        3: "Cryptographic Key Management",
        4: "Data Encryption/Decryption",
        5: "Policy-based Authorization",
        6: "Audit & Logging",
        7: "Proof of Sequential Access"
    }
    
    for layer_num in [2, 3, 4, 5, 6, 7]:
        print(f"  Traversing Layer {layer_num}: {layer_names[layer_num]}...")
        context = {}
        if layer_num == 5:
            context['permission'] = 'read'
        
        if chakra.traverse_layer('alice', layer_num, context):
            print(f"  ✓ Layer {layer_num} traversed successfully")
        else:
            print(f"  ✗ Layer {layer_num} traversal failed")
            return
        
        time.sleep(0.1)  # Small delay to ensure sequential timestamps
    print()
    
    # Step 6: Verify full access
    print("Step 6: Verifying complete Chakravyuh traversal...")
    if chakra.verify_full_access('alice'):
        print("✓ All 7 layers traversed successfully!")
        print("  - Sequential access verified")
        print("  - User has full access to protected assets")
    else:
        print("✗ Full access verification failed")
        return
    print()
    
    # Step 7: Decrypt the asset
    print("Step 7: Decrypting protected asset...")
    decrypted = chakra.decrypt_asset('alice', 'mission_critical_1')
    if decrypted:
        print("✓ Asset decrypted successfully!")
        print(f"  - Decrypted message: {decrypted.decode('utf-8')}")
    else:
        print("✗ Decryption failed")
    print()
    
    # Step 8: View audit trail
    print("Step 8: Retrieving audit trail...")
    audit = chakra.get_audit_trail('alice')
    print(f"✓ Audit trail retrieved")
    print(f"  - Total events logged: {len(audit['comprehensive_logs'])}")
    print(f"  - Layer proofs recorded: {len(audit['layer_proofs'])}")
    print()
    
    print("Recent audit events:")
    for event in audit['comprehensive_logs'][-5:]:
        event_time = time.strftime('%H:%M:%S', time.localtime(event['timestamp']))
        print(f"  [{event_time}] {event['event_type']} - {event['user_id']}")
    print()
    
    print("Layer traversal proofs:")
    for proof in sorted(audit['layer_proofs'], key=lambda p: p.layer_number):
        proof_time = time.strftime('%H:%M:%S', time.localtime(proof.timestamp))
        print(f"  Layer {proof.layer_number}: [{proof_time}] Hash: {proof.proof_hash[:16]}...")
    print()
    
    print("=" * 80)
    print("ChakraSec Demo Completed Successfully!")
    print("=" * 80)
    print()
    print("Summary:")
    print("  - The Chakravyuh pattern enforces sequential layer traversal")
    print("  - Sensitive assets are protected by multiple security layers")
    print("  - Each access is audited and cryptographically proven")
    print("  - Time-bound access ensures temporal security")
    print("  - Policy-based authorization provides fine-grained control")
    print()


if __name__ == '__main__':
    main()
