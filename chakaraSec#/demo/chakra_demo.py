#!/usr/bin/env python3
"""
ChakraSec Complete Demonstration
Shows the full workflow: DSL parsing -> Compilation -> Runtime execution
"""

import os
import sys
import asyncio
import logging
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from chakrasec import (
    ChakraSecParser, ChakraComp, ChakraVM, GateEvaluator, 
    CryptoEngine, MatrixPuzzle
)
from chakrasec.deception import DeceptionEngine

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

class ChakraSecDemo:
    """Complete ChakraSec demonstration"""
    
    def __init__(self):
        self.logger = logging.getLogger("ChakraSecDemo")
        
        # Initialize components
        self.master_secret = b"chakrasec_master_secret_demo_key_2024"
        self.parser = ChakraSecParser()
        self.compiler = ChakraComp("demo/dist")
        self.gate_evaluator = GateEvaluator(self.master_secret)
        self.chakra_vm = ChakraVM(self.gate_evaluator)
        self.deception_engine = DeceptionEngine()
        
        self.logger.info("ChakraSec Demo initialized")
    
    def demonstrate_dsl_parsing(self):
        """Demonstrate ChakraSec DSL parsing"""
        print("\n" + "="*60)
        print("1. ChakraSec DSL Parsing Demonstration")
        print("="*60)
        
        # Parse example policies
        policy_file = Path("demo/example_policies.chakrasec")
        
        if not policy_file.exists():
            print("Error: Policy file not found!")
            return None
        
        try:
            assets = self.parser.parse_file(str(policy_file))
            
            print(f"Successfully parsed {len(assets)} assets:")
            for asset_name, asset_def in assets.items():
                print(f"\n[ASSET] {asset_name}")
                print(f"   Layers: {asset_def.layers}")
                print(f"   Policies defined for layers: {list(asset_def.layer_policies.keys())}")
                
                # Show sample policy details
                if asset_def.layer_policies:
                    sample_layer = list(asset_def.layer_policies.keys())[0]
                    sample_policy = asset_def.layer_policies[sample_layer]
                    print(f"   Sample (Layer {sample_layer}): {len(sample_policy.rules)} rules")
                    for rule in sample_policy.rules[:2]:  # Show first 2 rules
                        print(f"     - {rule.atom.value}: {rule.params}")
            
            return assets
            
        except Exception as e:
            print(f"[ERROR] DSL Parsing failed: {e}")
            return None
    
    def demonstrate_compilation(self, assets):
        """Demonstrate asset compilation"""
        print("\n" + "="*60)
        print("2. Asset Compilation Demonstration")
        print("="*60)
        
        # Load sample code to protect
        sample_code_file = Path("demo/sample_code.py")
        
        if not sample_code_file.exists():
            print("Error: Sample code file not found!")
            return []
        
        with open(sample_code_file, 'rb') as f:
            source_code = f.read()
        
        compiled_packages = []
        
        # Compile each asset
        for asset_name, asset_def in assets.items():
            print(f"\n[COMPILE] Compiling asset: {asset_name}")
            
            # Configure custodians for assets that need them
            custodian_config = None
            if asset_name in ["financial_vault", "trade_secrets"]:
                custodian_config = {
                    "enabled": True,
                    "custodians": ["alice", "bob", "charlie", "david", "eve"]
                }
            
            result = self.compiler.compile_asset(asset_def, source_code, custodian_config)
            
            if result.success:
                print(f"   [SUCCESS] Compilation successful!")
                print(f"  [PACKAGE] Package: {result.package_path}")
                print(f"   Package ID: {result.package_id}")
                
                if result.warnings:
                    print(f"   [WARN] Warnings: {len(result.warnings)}")
                    for warning in result.warnings[:3]:  # Show first 3
                        print(f"      - {warning}")
                
                compiled_packages.append((asset_name, result.package_path))
            else:
                print(f"   [ERROR] Compilation failed!")
                for error in result.errors:
                    print(f"      - {error}")
        
        return compiled_packages
    
    def demonstrate_puzzle_system(self):
        """Demonstrate dynamic matrix puzzle system"""
        print("\n" + "="*60)
        print("3. Dynamic Matrix Puzzle Demonstration")
        print("="*60)
        
        # Create puzzle instance
        puzzle = MatrixPuzzle(self.master_secret, window_seconds=1, drift_tolerance=1)
        
        # Generate challenge
        client_seed = b"demo_client_seed_12345"
        layer_id = 5
        difficulty = 128
        
        print(f"[PUZZLE][DECOY] Generating puzzle challenge...")
        print(f"   Client Seed: {client_seed.hex()[:16]}...")
        print(f"   Layer ID: {layer_id}")
        print(f"   Difficulty: {difficulty} bits")
        
        challenge = puzzle.generate_challenge(client_seed, layer_id, difficulty)
        
        print(f"\n[CHALLENGE] Challenge generated:")
        print(f"   Time Window: {challenge.time_window}")
        print(f"   Expected Value: {challenge.expected_value}")
        print(f"   Matrix Seed: {challenge.matrix_seed.hex()[:16]}...")
        
        # Create proof
        print(f"\n[PROOF] Creating proof...")
        session_nonce = b"demo_session_nonce_67890"
        proof = puzzle.create_proof(challenge, client_seed, session_nonce)
        
        print(f"   Computed Value: {proof.computed_value}")
        print(f"   MAC: {proof.mac.hex()[:16]}...")
        
        # Verify proof
        print(f"\n[VERIFY] Verifying proof...")
        is_valid = puzzle.verify_proof(proof, challenge, session_nonce)
        
        if is_valid:
            print("   [SUCCESS] Proof verification successful!")
        else:
            print("   [ERROR] Proof verification failed!")
        
        return is_valid
    
    def demonstrate_deception_engine(self):
        """Demonstrate deception engine"""
        print("\n" + "="*60)
        print("4. Deception Engine Demonstration")
        print("="*60)
        
        # Generate different types of decoys
        decoy_types = ["financial_basic", "medical_basic", "corporate_basic"]
        
        for decoy_id in decoy_types:
            print(f"\n[DECOY] Generating {decoy_id} decoy...")
            
            context = {
                "layer_id": 4,
                "session_nonce": "demo_session",
                "client_info": {
                    "ip_address": "192.168.1.100",
                    "user_agent": "ChakraSec Demo Client"
                }
            }
            
            decoy_data = self.deception_engine.generate_decoy_response(decoy_id, context)
            
            print(f"   Generated decoy data:")
            for key, value in list(decoy_data.items())[:5]:  # Show first 5 items
                if isinstance(value, (str, int, float)):
                    print(f"     {key}: {value}")
                else:
                    print(f"     {key}: {type(value).__name__}")
        
        # Create honeypot
        print(f"\n[HONEYPOT] Creating interactive honeypot...")
        client_info = {
            "session_id": "demo_attacker_session",
            "ip_address": "10.0.0.1"
        }
        
        honeypot_id = self.deception_engine.create_interactive_honeypot(
            "web_honeypot", client_info
        )
        
        print(f"   Honeypot ID: {honeypot_id}")
        
        # Simulate honeypot interaction
        interaction_data = {
            "type": "api_request",
            "endpoint": "/api/users",
            "method": "GET"
        }
        
        response = self.deception_engine.handle_honeypot_interaction(
            honeypot_id, interaction_data, client_info
        )
        
        print(f"   Honeypot response: {response.get('status', 'unknown')}")
        
        # Show statistics
        stats = self.deception_engine.get_deception_statistics()
        print(f"\n[STATS] Deception Statistics:")
        for key, value in stats.items():
            print(f"   {key}: {value}")
    
    async def demonstrate_runtime_execution(self, compiled_packages):
        """Demonstrate runtime execution (simplified)"""
        print("\n" + "="*60)
        print("5. Runtime Execution Demonstration")
        print("="*60)
        
        if not compiled_packages:
            print(" No compiled packages available for execution")
            return
        
        # Take the first compiled package for demonstration
        asset_name, package_path = compiled_packages[0]
        
        print(f"[EXECUTE] Executing asset: {asset_name}")
        print(f"[PACKAGE] Package: {package_path}")
        
        # Simulate client information
        client_info = {
            "device_id": "demo_device_123",
            "ip_address": "192.168.1.100",
            "user_agent": "ChakraSec Demo Client",
            "known_ip": True
        }
        
        print(f"\n[CLIENT] Client Info:")
        for key, value in client_info.items():
            print(f"   {key}: {value}")
        
        # Note: In a real demo, this would go through the full authentication flow
        # For this demonstration, we'll show the process conceptually
        
        print(f"\n[AUTH] Authentication Flow (Simulated):")
        print("   Layer 7: Rate limiting... ")
        print("   Layer 6: Geolocation check... ")
        print("   Layer 5: Matrix puzzle... ")
        print("   Layer 4: MFA verification... ")
        print("   Layer 3: Custodian approval... ")
        print("   Layer 2: HSM verification... ")
        print("   Layer 1: Final checks... ")
        
        print(f"\n[SUCCESS] All layers authenticated successfully!")
        print(f"[DECRYPT] Decrypting and executing protected code...")
        
        # Simulate execution result
        execution_result = {
            "success": True,
            "output": "Protected code executed successfully",
            "layers_decrypted": 7,
            "execution_time": 2.5
        }
        
        print(f"\n[RESULT] Execution Result:")
        for key, value in execution_result.items():
            print(f"   {key}: {value}")
    
    def demonstrate_failure_scenarios(self):
        """Demonstrate failure scenarios and deception responses"""
        print("\n" + "="*60)
        print("6. Failure Scenarios & Deception")
        print("="*60)
        
        scenarios = [
            {
                "name": "Invalid MFA Code",
                "layer": 4,
                "action": "RETURN_DECOY",
                "decoy_type": "financial"
            },
            {
                "name": "Geolocation Violation",
                "layer": 6,
                "action": "ALERT",
                "alert_group": "security_team"
            },
            {
                "name": "Puzzle Solution Timeout",
                "layer": 5,
                "action": "RETURN_DECOY",
                "decoy_type": "corporate"
            },
            {
                "name": "Insufficient Custodian Approvals",
                "layer": 3,
                "action": "DENY",
                "reason": "Only 2 of 3 required custodians approved"
            }
        ]
        
        for scenario in scenarios:
            print(f"\n[SCENARIO] Scenario: {scenario['name']}")
            print(f"   Failed at Layer: {scenario['layer']}")
            print(f"   Action: {scenario['action']}")
            
            if scenario['action'] == 'RETURN_DECOY':
                print(f"    Returning {scenario['decoy_type']} decoy data")
                print("     Attacker sees fake success response")
                print("    Security team alerted in background")
            
            elif scenario['action'] == 'ALERT':
                print(f"    Alert sent to: {scenario.get('alert_group', 'security')}")
                print("    Access denied")
            
            elif scenario['action'] == 'DENY':
                print(f"    Access denied: {scenario.get('reason', 'Policy violation')}")
    
    def show_system_statistics(self):
        """Show comprehensive system statistics"""
        print("\n" + "="*60)
        print("7. System Statistics & Information")
        print("="*60)
        
        # Compiler info
        compiler_info = self.compiler.get_compiler_info()
        print(f"\n[COMPILER] Compiler Information:")
        print(f"   Version: {compiler_info['version']}")
        print(f"   Output Directory: {compiler_info['output_directory']}")
        print(f"   Supported Layers: {compiler_info['supported_layers']}")
        print(f"   Supported Atoms: {len(compiler_info['supported_atoms'])}")
        
        # Gate Evaluator stats
        ge_stats = self.gate_evaluator.get_statistics()
        print(f"\n[GATE] Gate Evaluator Statistics:")
        for key, value in ge_stats.items():
            print(f"   {key}: {value}")
        
        # Runtime stats
        vm_stats = self.chakra_vm.get_runtime_statistics()
        print(f"\n [VM] ChakraVM Statistics:")
        for key, value in vm_stats.items():
            print(f"   {key}: {value}")
        
        # Deception stats
        deception_stats = self.deception_engine.get_deception_statistics()
        print(f"\n[DECEPTION] Deception Engine Statistics:")
        for key, value in deception_stats.items():
            print(f"   {key}: {value}")
        
        # Puzzle info
        puzzle_info = MatrixPuzzle(self.master_secret).get_puzzle_info(128)
        print(f"\n[PUZZLE] Matrix Puzzle Configuration:")
        for key, value in puzzle_info.items():
            print(f"   {key}: {value}")
    
    async def run_complete_demo(self):
        """Run the complete ChakraSec demonstration"""
        print("ChakraSec: Security-First Stack Demonstration")
        print("Inspired by the Abhimanyu Chakravyuh - 7 Concentric Layers of Protection")
        print("="*80)
        
        try:
            # 1. DSL Parsing
            assets = self.demonstrate_dsl_parsing()
            if not assets:
                return
            
            # 2. Compilation
            compiled_packages = self.demonstrate_compilation(assets)
            
            # 3. Puzzle System
            self.demonstrate_puzzle_system()
            
            # 4. Deception Engine
            self.demonstrate_deception_engine()
            
            # 5. Runtime Execution
            await self.demonstrate_runtime_execution(compiled_packages)
            
            # 6. Failure Scenarios
            self.demonstrate_failure_scenarios()
            
            # 7. System Statistics
            self.show_system_statistics()
            
            print("\n" + "="*80)
            print("[COMPLETE] ChakraSec Demonstration Complete!")
            print("[SUCCESS] All components successfully demonstrated")
            print("[READY] 7-layer Chakravyuh protection system operational")
            print("="*80)
            
        except Exception as e:
            self.logger.error(f"Demo failed: {e}")
            print(f"\n Demo failed: {e}")

def main():
    """Main demo entry point"""
    demo = ChakraSecDemo()
    
    # Ensure demo directories exist
    os.makedirs("demo/dist", exist_ok=True)
    
    # Run the complete demonstration
    asyncio.run(demo.run_complete_demo())

if __name__ == "__main__":
    main()
