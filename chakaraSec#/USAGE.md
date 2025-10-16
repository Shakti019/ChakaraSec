# ChakraSec Usage Guide

## Overview

ChakraSec is a revolutionary security-first stack that protects assets through 7 concentric cryptographic layers, inspired by the Abhimanyu Chakravyuh. Each layer requires sequential, time-bound, policy-based proofs before granting access to the next layer.

## Quick Start

### 1. Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Run the complete demonstration
python demo/chakra_demo.py

# Run tests
python tests/test_chakrasec.py
```

### 2. Basic Usage

#### Define Security Policies (ChakraSec DSL)

Create a `.chakrasec` file with your security policies:

```chakrasec
asset "financial_vault" {
    layers = 7;
    
    layer 7 {
        policy = RATE_LIMIT(5, 60) && TIME_WINDOW("09:00", "17:00");
        action_on_fail = ALERT("security_team");
    }
    
    layer 6 {
        policy = GEO(40.7128, -74.0060, 1000) && DEVICE("device_pubkey");
        action_on_fail = RETURN_DECOY("financial");
    }
    
    layer 5 {
        policy = PUZZLE("matrix", 128);
        action_on_fail = RETURN_DECOY("financial");
    }
    
    layer 4 {
        policy = MFA(2) && RISK_LEQ(0.3);
        action_on_fail = ALERT("fraud_team");
    }
    
    layer 3 {
        policy = THRESHOLD(3, ["alice", "bob", "charlie", "david", "eve"]);
        action_on_fail = DENY();
    }
    
    layer 2 {
        policy = HSM_UNSEAL("master_key") && MFA(3);
        action_on_fail = DENY();
    }
    
    layer 1 {
        policy = MFA(3) && DEVICE("secure_key") && TIME_WINDOW("10:00", "16:00");
        action_on_fail = DENY();
    }
}
```

#### Compile Protected Assets

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

#### Execute Protected Assets

```python
from chakrasec import ChakraVM, GateEvaluator
import asyncio

# Initialize components
master_secret = b"your_master_secret_here"
gate_evaluator = GateEvaluator(master_secret)
chakra_vm = ChakraVM(gate_evaluator)

# Execute protected package
async def execute_protected_asset():
    client_info = {
        "device_id": "trusted_device_123",
        "ip_address": "192.168.1.100",
        "user_agent": "ChakraSec Client v1.0"
    }
    
    result = await chakra_vm.execute_package(
        "path/to/package.ccv",
        client_info
    )
    
    if result.success:
        print("Protected code executed successfully!")
        print(f"Output: {result.output}")
    else:
        print(f"Execution failed: {result.errors}")

# Run execution
asyncio.run(execute_protected_asset())
```

## Policy Atoms Reference

### Authentication & Identity

- **MFA(level)**: Multi-factor authentication requirement
  - `level`: Required MFA level (1-3)
  - Example: `MFA(2)` requires 2FA

- **DEVICE(pubkey)**: Device attestation
  - `pubkey`: Required device public key
  - Example: `DEVICE("device_key_abc123")`

### Time & Location

- **TIME_WINDOW(start, end)**: Time-based access control
  - `start`, `end`: Time range in HH:MM format
  - Example: `TIME_WINDOW("09:00", "17:00")`

- **GEO(lat, lon, radius)**: Geolocation constraint
  - `lat`, `lon`: GPS coordinates
  - `radius`: Allowed radius in meters
  - Example: `GEO(40.7128, -74.0060, 1000)`

### Cryptographic Challenges

- **PUZZLE(type, difficulty)**: Dynamic cryptographic puzzle
  - `type`: Puzzle type ("matrix")
  - `difficulty`: Entropy bits (32, 64, 128, 256)
  - Example: `PUZZLE("matrix", 128)`

### Governance & Custody

- **THRESHOLD(t, custodians)**: Custodian approval threshold
  - `t`: Required number of approvals
  - `custodians`: List of custodian IDs
  - Example: `THRESHOLD(3, ["alice", "bob", "charlie", "david"])`

- **HSM_UNSEAL(key_id)**: Hardware Security Module requirement
  - `key_id`: HSM key identifier
  - Example: `HSM_UNSEAL("master_key_001")`

### Risk & Rate Limiting

- **RISK_LEQ(threshold)**: Risk assessment constraint
  - `threshold`: Maximum allowed risk score (0.0-1.0)
  - Example: `RISK_LEQ(0.3)`

- **RATE_LIMIT(count, seconds)**: Rate limiting
  - `count`: Maximum requests
  - `seconds`: Time window
  - Example: `RATE_LIMIT(10, 60)`

## Failure Actions

- **ALLOW_EXECUTE**: Grant access (default success action)
- **DENY()**: Explicitly deny access
- **RETURN_DECOY(type)**: Return deceptive response
  - Types: "financial", "medical", "corporate", "technical"
- **ALERT(group)**: Trigger security alert
  - Groups: "security_team", "fraud_team", "legal_team", etc.

## Architecture Components

### ChakraSec DSL
Declarative security language for defining layer policies.

### ChakraComp (Compiler)
Transforms source code and policies into 7-layer encrypted packages (.ccv files).

### Gate Evaluator (GE)
Service that verifies proofs and issues single-use release tokens.

### ChakraVM (Runtime)
Executes protected assets by sequentially decrypting layers after verification.

### Matrix Puzzle System
Dynamic per-second cryptographic challenges that change continuously.

### Deception Engine
Provides sophisticated decoy responses and honeypot functionality.

## Security Properties

### Confidentiality
- AES-GCM encryption for each layer
- Keys only released after policy verification
- Perfect forward secrecy through single-use tokens

### Integrity
- Ed25519 signatures for package integrity
- HMAC protection for all metadata
- Cryptographic commitments for key binding

### Availability
- Graceful degradation with decoy responses
- Rate limiting to prevent DoS attacks
- Distributed custodian architecture

### Auditability
- Comprehensive audit logging
- Non-repudiation through digital signatures
- Tamper-evident package format

## Advanced Features

### Custodian Key Splitting

```python
# Configure Shamir secret sharing
custodian_config = {
    "enabled": True,
    "custodians": ["alice", "bob", "charlie", "david", "eve"],
    "threshold": 3  # Require 3 of 5 custodians
}

result = compiler.compile_asset(asset_def, source_code, custodian_config)
```

### Dynamic Puzzle Configuration

```python
from chakrasec.puzzle import MatrixPuzzle

# Create puzzle with custom parameters
puzzle = MatrixPuzzle(
    master_secret=b"puzzle_master_secret",
    window_seconds=1,      # Change every second
    drift_tolerance=2      # Allow ±2 seconds for network delays
)

# Generate challenge
challenge = puzzle.generate_challenge(
    client_seed=b"client_seed",
    layer_id=5,
    difficulty=256  # 256-bit entropy
)
```

### Deception Responses

```python
from chakrasec.deception import DeceptionEngine

deception = DeceptionEngine()

# Generate financial decoy
decoy_data = deception.generate_decoy_response("financial_basic", {
    "layer_id": 4,
    "client_info": {"ip_address": "suspicious_ip"}
})

# Create interactive honeypot
honeypot_id = deception.create_interactive_honeypot("web_honeypot", client_info)
```

## Best Practices

### Policy Design

1. **Layer Defense Strategy**:
   - Outer layers (L7-L5): Filtering and basic verification
   - Middle layers (L4-L3): Strong authentication and governance
   - Inner layers (L2-L1): Final verification and HSM protection

2. **Multi-Factor Policies**:
   - Combine different atom types: `MFA(2) && DEVICE(key) && GEO(lat, lon, r)`
   - Use progressive difficulty: easier outer layers, stricter inner layers

3. **Failure Handling**:
   - Use `RETURN_DECOY` for outer layers to confuse attackers
   - Use `ALERT` for suspicious activity detection
   - Use `DENY` for critical inner layers

### Operational Security

1. **Key Management**:
   - Use HSMs for master secrets in production
   - Implement proper key rotation procedures
   - Secure custodian key distribution

2. **Monitoring**:
   - Monitor all verification attempts
   - Set up alerts for repeated failures
   - Track honeypot interactions

3. **Performance**:
   - Tune puzzle difficulty based on client capabilities
   - Adjust time windows for network conditions
   - Use appropriate rate limits

## Troubleshooting

### Common Issues

1. **Compilation Errors**:
   - Check DSL syntax
   - Verify all layers have policies
   - Ensure custodian configuration is valid

2. **Runtime Failures**:
   - Verify client certificates and keys
   - Check network connectivity to Gate Evaluator
   - Validate time synchronization for puzzles

3. **Performance Issues**:
   - Reduce puzzle difficulty for slower clients
   - Increase time window tolerance
   - Optimize custodian response times

### Debug Mode

```python
import logging
logging.basicConfig(level=logging.DEBUG)

# Enable detailed logging for all components
```

## Examples

See the `demo/` directory for complete examples:

- `example_policies.chakrasec`: Sample policy definitions
- `sample_code.py`: Protected code examples
- `chakra_demo.py`: Complete demonstration script

## API Reference

For detailed API documentation, see the docstrings in each module:

- `chakrasec.dsl`: DSL parsing and policy definitions
- `chakrasec.compiler`: Asset compilation
- `chakrasec.runtime`: Protected execution
- `chakrasec.gate_evaluator`: Proof verification
- `chakrasec.crypto`: Cryptographic operations
- `chakrasec.puzzle`: Dynamic puzzle system
- `chakrasec.deception`: Deception engine
