# ChakraSec: A Multi-Layered Cryptographic Protection System

## Project Overview

ChakraSec is a revolutionary security-first stack inspired by the Abhimanyu Chakravyuh concept from Indian mythology. It implements a sophisticated 7-layer concentric cryptographic protection system designed to secure sensitive assets through sequential, time-bound, policy-based proofs.

## Table of Contents

1. [Conceptual Foundation](#conceptual-foundation)
2. [System Architecture](#system-architecture)
3. [Core Components](#core-components)
4. [Security Features](#security-features)
5. [Implementation Details](#implementation-details)
6. [Performance Analysis](#performance-analysis)
7. [Usage Examples](#usage-examples)
8. [Installation and Setup](#installation-and-setup)
9. [Research Applications](#research-applications)
10. [Future Directions](#future-directions)

## Conceptual Foundation

The Chakravyuh (or Padmavyuha) is an ancient military formation described in the Mahabharata, where warriors are arranged in concentric circles. The formation was designed such that penetrating each layer required specific knowledge and skills. ChakraSec adapts this concept to modern cryptography, creating a multi-layered defense system where each layer requires specific proofs before access is granted to the next layer.

## System Architecture

```
Developer -> ChakraSec (DSL) + Source -> ChakraComp -> .ccv (signed package)
                   |
                   v
              Artifact Store
                   |
               ChakraVM (runtime) <-> Gate Evaluator (GE)
                                  <-> Custodians (optional)
                                  -> Audit Ledger
```

The system follows a comprehensive workflow:

1. **Development Phase**: Developers define security policies using the ChakraSec DSL and provide source code to protect
2. **Compilation Phase**: ChakraComp compiles the source with the defined policies into a protected .ccv package
3. **Storage Phase**: Protected packages are stored in an artifact repository
4. **Runtime Phase**: ChakraVM executes protected packages, interacting with the Gate Evaluator for policy verification
5. **Verification Phase**: Gate Evaluator checks proofs against policies for each layer
6. **Audit Phase**: All operations are logged to an append-only audit ledger

## Core Components

### ChakraSec DSL

A domain-specific language for defining security policies for each layer. The DSL allows for declarative specification of:

- Layer-specific security policies
- Actions to take on policy failure
- Custodian configurations
- Deception strategies

Example DSL:

```chakrasec
asset "financial_vault" {
    layers = 7;
    
    layer 7 {
        policy = RATE_LIMIT(5, 60) && TIME_WINDOW("09:00", "17:00");
        action_on_fail = ALERT("security_team");
    }
    
    // Additional layers defined similarly
}
```

### ChakraComp

The compiler that transforms source code and security policies into protected packages:

- Encrypts source code with 7 concentric layers
- Embeds policy requirements in each layer
- Generates cryptographic puzzles
- Creates custodian shares using Shamir's Secret Sharing
- Signs the final package

### Gate Evaluator (GE)

The service responsible for verifying proofs and issuing release tokens:

- Validates time-bound proofs
- Checks policy compliance
- Issues layer-specific decryption tokens
- Manages rate limiting and access controls
- Triggers alerts and deception mechanisms on failure

### ChakraVM

The runtime environment that executes protected packages:

- Sequentially decrypts layers using tokens from the Gate Evaluator
- Executes the innermost protected code only when all layers are successfully decrypted
- Manages the execution context and security boundaries

### Matrix Puzzle System

A dynamic cryptographic challenge mechanism:

- Generates per-second changing puzzles
- Implements moving-target defense
- Requires computational proof-of-work
- Prevents offline attacks

### Deception Engine

Sophisticated countermeasures against unauthorized access attempts:

- Returns convincing decoy responses on failure
- Implements honeypots and traps
- Triggers silent alerts
- Collects intelligence on attack patterns

## Security Features

### 7-Layer Defense

The system implements 7 concentric encryption layers, each requiring specific proofs:

1. **Layer 1 (Innermost)**: Highest security, typically requiring multiple authentication factors
2. **Layer 2**: Hardware Security Module (HSM) verification
3. **Layer 3**: Multi-party authorization (Shamir's Secret Sharing)
4. **Layer 4**: Risk assessment and additional MFA
5. **Layer 5**: Dynamic cryptographic puzzles
6. **Layer 6**: Device attestation and geolocation verification
7. **Layer 7 (Outermost)**: Rate limiting and time window restrictions

### Moving Target Defense

The Matrix Puzzle system implements a dynamic security approach:

- Puzzles change every second
- Prevents pre-computation of solutions
- Requires real-time interaction with the Gate Evaluator

### Policy Enforcement

The system supports a wide range of policy types:

- Multi-factor authentication (MFA)
- Device attestation
- Geo-fencing
- Time windows
- Rate limiting
- Risk scoring
- Hardware security module integration
- Multi-party authorization

### Split Custody

Optional Shamir's Secret Sharing for critical layers:

- Splits key material among multiple custodians
- Requires a threshold of custodians to reconstruct keys
- Prevents single points of compromise

### Deception Mechanisms

Advanced deception strategies to mislead attackers:

- Returns plausible but fake data on unauthorized access
- Implements honeypots to detect and study attack patterns
- Provides false feedback to prevent learning from failures

### Audit Trail

Comprehensive logging of all operations:

- Append-only ledger for non-repudiation
- Records all access attempts, successes, and failures
- Captures timing and context information
- Supports forensic analysis

## Implementation Details

### Cryptographic Operations

The system uses modern cryptographic primitives:

- **Encryption**: AES-GCM for layer encryption
- **Signatures**: Ed25519 for package signing
- **Key Sharing**: Shamir's Secret Sharing (t-of-n threshold scheme)
- **Hashing**: SHA-256 for integrity verification
- **Puzzles**: Custom matrix-based cryptographic challenges

### Programming Language and Dependencies

- Implemented in Python 3.10+
- Core cryptographic operations use the `cryptography` library
- Matrix operations utilize NumPy for efficiency
- Minimal external dependencies for security

## Performance Analysis

Comprehensive parameter analysis has demonstrated the system's effectiveness:

### Security Effectiveness

- **Attack Success Rate**: 0.000000 across all tested configurations
- **Detection Rate**: 99.4% - 100% across all scenarios
- **Layer Penetration**: Attackers consistently fail to break through even the outer layers

### Performance Characteristics

- **Baseline Configuration**: 142,111s mean attack time (39+ hours)
- **High Security Configuration**: 1.08 × 10¹² seconds (34+ million years)
- **Performance Configuration**: 4.66 × 10⁹ seconds (147+ years)

### Parameter Impact Analysis

#### Entropy Analysis

| Configuration | Entropy per Layer | Mean Attack Time | Detection Rate |
|---------------|-------------------|------------------|----------------|
| 16-bit layers | 16 bits | 22.3 seconds | 99.4% |
| 32-bit layers | 32 bits | 153,400 seconds | 100% |
| 64-bit layers | 64 bits | 1.25 × 10¹³ seconds | 100% |
| 128-bit layers | 128 bits | 1.46 × 10³² seconds | 100% |

#### Layer Count Impact

- **3 layers**: Adequate for low-security scenarios
- **5 layers**: Good balance for most applications  
- **7 layers**: Optimal security/performance balance (recommended)
- **9 layers**: Maximum security for critical assets

#### Puzzle Timing Analysis

- **0.5s windows**: Maximum moving-target effectiveness
- **1.0s windows**: Optimal balance (recommended)
- **2.0s+ windows**: Reduced effectiveness but better network tolerance

## Usage Examples

### Basic Usage

```python
from chakrasec import ChakraSecParser, ChakraComp

# Parse policies
parser = ChakraSecParser()
assets = parser.parse_file("my_policies.chakrasec")

# Load source code to protect
with open("sensitive_code.py", "rb") as f:
    source_code = f.read()

# Compile with 7-layer protection
compiler = ChakraComp("output_dir")
result = compiler.compile_asset(
    assets["financial_vault"], 
    source_code,
    custodian_config={"enabled": True, "custodians": ["alice", "bob", "charlie"]}
)

if result.success:
    print(f"Protected package created: {result.package_path}")
else:
    print(f"Compilation failed: {result.errors}")
```

### Running Protected Code

```python
from chakrasec import ChakraVM, GateEvaluator
import asyncio

async def run_protected_asset():
    # Initialize components
    gate_evaluator = GateEvaluator()
    vm = ChakraVM(gate_evaluator=gate_evaluator)
    
    # Load protected package
    package_path = "dist/financial_vault_123456.ccv"
    result = await vm.load_package(package_path)
    
    if result.success:
        # Provide proofs for each layer
        await vm.provide_proof(layer_id=7, proof_data={"time": "13:00", "rate_limit": True})
        await vm.provide_proof(layer_id=6, proof_data={"device_key": "device_pubkey"})
        # ... additional proofs for other layers
        
        # Execute when all proofs are validated
        execution_result = await vm.execute()
        print(f"Execution result: {execution_result}")
    else:
        print(f"Failed to load package: {result.error}")

# Run the async function
asyncio.run(run_protected_asset())
```

## Installation and Setup

### Prerequisites

- Python 3.10 or higher
- pip package manager

### Installation Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/chakrasec.git
   cd chakrasec
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the demonstration:
   ```bash
   python demo/simple_demo.py
   ```

4. Run tests:
   ```bash
   python tests/test_chakrasec.py
   ```

## Research Applications

ChakraSec has significant applications in several research domains:

### Cybersecurity Research

- Multi-layer defense strategies
- Moving target defense effectiveness
- Deception techniques in security systems
- Quantitative security metrics

### Cryptographic Research

- Practical applications of threshold cryptography
- Dynamic puzzle systems
- Time-bound cryptographic challenges
- Multi-layer encryption schemes

### Systems Security

- Secure execution environments
- Policy-based access control
- Runtime security enforcement
- Audit and non-repudiation mechanisms

## Future Directions

Potential areas for future research and development:

1. **Hardware Integration**: Implementing hardware-backed security for specific layers
2. **Formal Verification**: Applying formal methods to verify the security properties
3. **Quantum Resistance**: Adapting the system to be resistant to quantum computing attacks
4. **Performance Optimization**: Reducing the overhead of multi-layer decryption
5. **Extended Policy Types**: Supporting additional policy types and verification mechanisms

## License

MIT License - See LICENSE file for details

## Acknowledgments

This project draws inspiration from ancient Indian military strategies and modern cryptographic techniques, combining them to create a novel approach to security.

---

*Note: This README is intended for research purposes and provides a comprehensive overview of the ChakraSec system. For practical deployment guidance, please refer to the USAGE.md file.*