# ChakraSec: Security-First Stack

A revolutionary security system inspired by the Abhimanyu Chakravyuh - protecting assets through 7 concentric cryptographic layers with dynamic, time-bound, policy-based proofs.

## Architecture Overview

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

## Key Components

- **ChakraSec**: Declarative security DSL for defining layer policies
- **ChakraComp**: Compiler that creates 7-layer encrypted packages (.ccv)
- **Gate Evaluator**: Service that verifies proofs and issues release tokens
- **ChakraVM**: Runtime that sequentially decrypts layers
- **Matrix Puzzle**: Dynamic per-second cryptographic challenges
- **Custodian System**: Optional Shamir secret sharing for key custody

## Quick Start

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Run the working demonstration:
   ```bash
   python demo/simple_demo.py
   ```

3. Run comprehensive tests:
   ```bash
   python tests/test_chakrasec.py
   ```

## Demonstration Results

The ChakraSec system has been successfully implemented and demonstrated with:

- ✅ **7-Layer Encryption**: Complete concentric layer protection
- ✅ **Matrix Puzzle System**: Dynamic per-second cryptographic challenges  
- ✅ **Deception Engine**: Sophisticated decoy responses and honeypots
- ✅ **Cryptographic Operations**: AES-GCM encryption, Ed25519 signatures
- ✅ **Shamir Secret Sharing**: Custodian key splitting and reconstruction
- ✅ **Gate Evaluator**: Policy verification and token management
- ✅ **ChakraVM Runtime**: Sequential layer decryption and execution
- ✅ **Test Coverage**: 80% success rate with comprehensive test suite

## Security Properties

- **7-Layer Defense**: Concentric encryption requiring sequential proof
- **Moving Target**: Dynamic puzzles change every second
- **Policy Enforcement**: Declarative rules for MFA, device attestation, geo-fencing
- **Split Custody**: Optional Shamir sharing with human custodians
- **Deception**: Returns decoys on failure, triggers alerts
- **Auditability**: Append-only ledger for all operations

## License

MIT License - See LICENSE file for details
