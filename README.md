# ChakraSec: A Multi-Layered Cryptographic Protection System

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)

ChakraSec is a revolutionary security-first protection system inspired by the **Abhimanyu Chakravyuh** concept from Indian mythology. It implements a sophisticated **7-layer concentric cryptographic protection system** designed to secure sensitive assets through sequential, time-bound, and policy-based proofs.

## 🎯 Overview

In the Mahabharata, the Chakravyuh (also known as Padmavyuha) was a formidable military formation consisting of seven concentric circles, each presenting its own unique challenge. Similarly, ChakraSec creates a multi-layered security perimeter where access to protected assets requires successfully traversing all seven layers in sequential order.

### The Seven Layers

```
        ┌─────────────────────────────────────┐
        │  Layer 7: Sequential Proof          │
        │  ┌───────────────────────────────┐  │
        │  │  Layer 6: Audit & Logging     │  │
        │  │  ┌─────────────────────────┐  │  │
        │  │  │ Layer 5: Authorization  │  │  │
        │  │  │ ┌─────────────────────┐ │  │  │
        │  │  │ │ Layer 4: Encryption │ │  │  │
        │  │  │ │ ┌─────────────────┐ │ │  │  │
        │  │  │ │ │ Layer 3: Keys   │ │ │  │  │
        │  │  │ │ │ ┌─────────────┐ │ │ │  │  │
        │  │  │ │ │ │ Layer 2:    │ │ │ │  │  │
        │  │  │ │ │ │ Time-based  │ │ │ │  │  │
        │  │  │ │ │ │ ┌─────────┐ │ │ │ │  │  │
        │  │  │ │ │ │ │ Layer 1 │ │ │ │ │  │  │
        │  │  │ │ │ │ │  Auth   │ │ │ │ │  │  │
        │  │  │ │ │ │ │ [Asset] │ │ │ │ │  │  │
        │  │  │ │ │ │ └─────────┘ │ │ │ │  │  │
        │  │  │ │ │ └─────────────┘ │ │ │  │  │
        │  │  │ │ └─────────────────┘ │ │  │  │
        │  │  │ └─────────────────────┘ │  │  │
        │  │  └─────────────────────────┘  │  │
        │  └───────────────────────────────┘  │
        └─────────────────────────────────────┘
```

1. **Layer 1: Authentication & Identity Verification**
   - Secure user authentication with PBKDF2 password hashing
   - Identity verification with salted password storage
   - Failed attempt tracking and logging

2. **Layer 2: Time-bound Access Control**
   - Temporal access windows with configurable duration
   - Automatic expiration of access tokens
   - Time-based security enforcement

3. **Layer 3: Cryptographic Key Management**
   - Per-user cryptographic key generation
   - Key derivation using PBKDF2 with SHA-256
   - Secure key storage and retrieval

4. **Layer 4: Data Encryption/Decryption**
   - Symmetric encryption using Fernet (AES-128)
   - Per-asset encryption with unique identifiers
   - Secure data-at-rest protection

5. **Layer 5: Policy-based Authorization**
   - Role-based access control (RBAC)
   - Fine-grained permission management
   - Hierarchical role system (guest, user, admin)

6. **Layer 6: Audit & Logging**
   - Comprehensive event logging
   - Cryptographic event hashing for integrity
   - User-specific audit trails

7. **Layer 7: Proof of Sequential Access**
   - Cryptographic proof of layer traversal
   - Sequential access verification
   - Prevents layer-skipping attacks

## ✨ Key Features

- **Sequential Security**: Assets can only be decrypted after successfully traversing all 7 layers in order
- **Time-bound Protection**: Access windows expire automatically, ensuring temporal security
- **Cryptographic Proofs**: Each layer traversal generates a cryptographic proof
- **Comprehensive Auditing**: Every action is logged with cryptographic integrity
- **Multi-user Isolation**: Each user has isolated keys and access controls
- **Role-based Authorization**: Fine-grained permission control based on user roles
- **Defense in Depth**: Multiple independent security layers protect assets

## 🚀 Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Install Dependencies

```bash
pip install -r requirements.txt
```

## 📖 Usage

### Basic Example

```python
from chakrasec import ChakraSec
import time

# Initialize ChakraSec
chakra = ChakraSec()

# Register a user
chakra.register_user('alice', 'password123', role='admin')

# Authenticate
chakra.authenticate_user('alice', 'password123')

# Encrypt sensitive data
secret = b"Top secret information"
chakra.encrypt_asset('alice', secret, 'asset1')

# Traverse remaining layers
for layer in range(2, 8):
    chakra.traverse_layer('alice', layer)
    time.sleep(0.01)  # Small delay for sequential timestamps

# Verify full access
if chakra.verify_full_access('alice'):
    # Decrypt the asset
    decrypted = chakra.decrypt_asset('alice', 'asset1')
    print(decrypted)  # b"Top secret information"
```

### Running the Example

```bash
python example.py
```

This will demonstrate:
- User registration and authentication
- Asset encryption
- Sequential layer traversal
- Access verification
- Asset decryption
- Audit trail generation

## 🧪 Testing

Run the comprehensive test suite:

```bash
python -m unittest test_chakrasec.py -v
```

The test suite includes:
- Unit tests for each individual layer
- Integration tests for complete workflows
- Multi-user isolation tests
- Sequential access verification tests
- Edge case and failure scenario tests

## 🏗️ Architecture

### Layer Details

#### Layer 1: Authentication
- Uses PBKDF2 with SHA-256 for password hashing
- 100,000 iterations for enhanced security
- Random salt generation per user
- Resistant to rainbow table attacks

#### Layer 2: Time-based Access
- Configurable time windows (default: 1 hour)
- Automatic expiration checking
- Prevents unauthorized access after time limit

#### Layer 3: Key Management
- Derives 256-bit keys from master passwords
- Per-user key isolation
- Uses PBKDF2 with user ID as salt

#### Layer 4: Encryption
- Fernet symmetric encryption (AES-128)
- Timestamp-based key rotation support
- Secure data-at-rest protection

#### Layer 5: Authorization
- Three-tier role hierarchy: guest, user, admin
- Permission-based access control
- Extensible policy framework

#### Layer 6: Auditing
- SHA-256 event hashing
- Tamper-evident log chains
- Per-user audit trail retrieval

#### Layer 7: Sequential Proofs
- Cryptographic proof generation per layer
- Timestamp-based sequential verification
- Prevents out-of-order access

### Security Model

The ChakraSec security model is based on the principle of **defense in depth**:

1. **Authentication** verifies identity
2. **Time-bounds** ensure temporal validity
3. **Keys** provide cryptographic foundation
4. **Encryption** protects data confidentiality
5. **Authorization** enforces access policies
6. **Auditing** ensures accountability
7. **Proofs** guarantee sequential access

All seven layers must be successfully traversed in order to access protected assets.

## 🔒 Security Considerations

### Strengths

- **Multi-layered Protection**: Multiple independent security mechanisms
- **Sequential Enforcement**: Prevents layer-skipping attacks
- **Cryptographic Integrity**: Strong encryption and hashing
- **Audit Trail**: Complete access history with tamper evidence
- **Time-bound Security**: Automatic access expiration

### Limitations

- **In-Memory Storage**: Current implementation stores data in memory (not persistent)
- **Single-Node**: Not designed for distributed systems
- **Performance**: Seven-layer verification adds latency
- **Key Management**: Simplified key derivation (production systems need HSM)

### Best Practices

1. **Use Strong Passwords**: Minimum 12 characters with mixed case, numbers, and symbols
2. **Secure Master Passwords**: Store master passwords separately from user passwords
3. **Monitor Audit Logs**: Regularly review access patterns
4. **Set Appropriate Time Windows**: Balance security and usability
5. **Implement Persistence**: Add database backend for production use
6. **Rotate Keys**: Periodically regenerate cryptographic keys
7. **Limit Failed Attempts**: Implement account lockout after repeated failures

## 📚 API Reference

### ChakraSec Class

#### `register_user(user_id: str, password: str, role: str = 'user')`
Register a new user in the system.

#### `authenticate_user(user_id: str, password: str, master_password: str = None) -> bool`
Authenticate a user and initialize their session.

#### `traverse_layer(user_id: str, layer_number: int, context: Dict[str, Any] = None) -> bool`
Traverse a specific security layer.

#### `encrypt_asset(user_id: str, data: bytes, asset_id: str) -> Optional[bytes]`
Encrypt a sensitive asset.

#### `decrypt_asset(user_id: str, asset_id: str) -> Optional[bytes]`
Decrypt an asset (requires complete layer traversal).

#### `verify_full_access(user_id: str) -> bool`
Verify that user has traversed all seven layers.

#### `get_audit_trail(user_id: str) -> Dict[str, Any]`
Retrieve comprehensive audit information for a user.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

### Development Setup

```bash
git clone https://github.com/Shakti019/ChakaraSec.git
cd ChakaraSec
pip install -r requirements.txt
python -m unittest discover
```

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Inspired by the Chakravyuh (Padmavyuha) formation from the Mahabharata
- Built with the `cryptography` library for secure encryption
- Follows defense-in-depth security principles

## 📧 Contact

For questions or support, please open an issue on GitHub.

---

**Note**: This is a demonstration implementation. For production use, additional hardening, persistent storage, and security audits are recommended.
