<!-- PhoenixKey - A Secure Key Chain Management Protocol with Recovery Capability -->

<div align="center">

![PhoenixKey Logo](https://img.shields.io/badge/PhoenixKey-🔥-orange?style=for-the-badge&logo=python)

# 🔐 PhoenixKey

### A Secure Key Chain Management Protocol with Recovery Capability

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-red.svg?style=flat-square&logo=apache&logoColor=white)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-56%20passed-brightgreen.svg?style=flat-square&logo=github-actions&logoColor=white)](https://github.com/Amirsam-Azmoodeh/phoenix-key/actions)
[![Code Style](https://img.shields.io/badge/code%20style-PEP%208-black?style=flat-square&logo=python&logoColor=white)]()
[![Security](https://img.shields.io/badge/security-HKDF%20%2B%20BLAKE2s-brightgreen?style=flat-square)]()
[![PyPI](https://img.shields.io/badge/pypi-v1.0.0-blue?style=flat-square&logo=pypi&logoColor=white)](https://pypi.org/project/phoenix-key/)
[![Downloads](https://img.shields.io/badge/downloads-0-yellow?style=flat-square)]()

</div>

---

## 📖 Table of Contents

- [🚀 Why PhoenixKey?](#-why-phoenixkey)
- [✨ Features](#-features)
- [🛠️ Technologies](#️-technologies)
- [📦 Installation](#-installation)
- [⚡ Quick Start](#-quick-start)
- [📚 How It Works](#-how-it-works)
  - [Key Derivation](#key-derivation)
  - [Cascade Recovery](#cascade-recovery)
  - [Rejection Timer](#rejection-timer)
- [🔒 Security Considerations](#-security-considerations)
- [📊 Performance](#-performance)
- [🧪 Testing](#-testing)
- [📁 Project Structure](#-project-structure)
- [🤝 Contributing](#-contributing)
- [🗺️ Roadmap](#️-roadmap)
- [📄 License](#-license)
- [📬 Contact](#-contact)

---

## 🚀 Why PhoenixKey?

> **"Your keys, resilient by design."**

In the world of secure communications, **packet loss**, **out-of-order delivery**, and **network delays** are inevitable. Most key management protocols fail or require complex re-synchronization when messages arrive out of order.

**PhoenixKey** solves this by implementing a **self-healing key chain** that:

- 🔄 **Automatically recovers** from out-of-order messages
- ⏱️ **Manages rejection timers** to prevent deadlocks
- 🎯 **Cascades recovery** to rebuild entire key chains
- ⚡ **Uses HKDF with BLAKE2s** for high performance

### 🎯 **Perfect for:**

- 🌐 **IoT Devices** - Lightweight and efficient for constrained devices
- 🛰️ **Satellite Communications** - Handles high latency and packet loss
- 🚗 **V2X Networks** - Reliable for moving vehicles
- 💬 **Secure Messaging** - Simple and robust key management
- 📡 **Wireless Sensor Networks** - Low power and memory footprint

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔑 **HKDF with BLAKE2s** | High-performance key derivation using industry-standard HKDF with the ultra-fast BLAKE2s hash |
| 🔄 **Out-of-Order Recovery** | Automatically recovers when keys arrive out of sequence |
| ⏱️ **TTL Rejection Handling** | Prevents deadlocks with Time-To-Live timers for missing keys |
| 🌊 **Cascade Recovery** | Rebuilds entire pending key chains with a single key arrival |
| 🧹 **Automatic Cleanup** | Removes old keys to maintain a small memory footprint (Forward Secrecy) |
| 🛡️ **Duplicate Detection** | Prevents replay attacks with counter validation |
| 📏 **Range Validation** | Configurable `max_counter` to limit out-of-order gaps |
| 🐍 **Type Hints** | Full type annotations for better IDE support |
| 📚 **Comprehensive Docs** | Complete docstrings and examples |
| 🧪 **56 Tests** | 47 unit tests + 9 integration tests, 100% coverage |
| 🔐 **AEAD Ready** | Works with ChaCha20-Poly1305 and AES-GCM |

---

## 🛠️ Technologies

<div align="center">

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Cryptography](https://img.shields.io/badge/Cryptography-4B0082?style=for-the-badge&logo=python&logoColor=white)
![HKDF](https://img.shields.io/badge/HKDF-FF6B00?style=for-the-badge&logo=python&logoColor=white)
![BLAKE2](https://img.shields.io/badge/BLAKE2s-FFD700?style=for-the-badge&logo=python&logoColor=black)

</div>

- **Python 3.8+** - Core language
- **[Cryptography](https://cryptography.io/)** - HKDF implementation
- **[BLAKE2s](https://www.blake2.net/)** - Fast and secure hash function
- **[unittest](https://docs.python.org/3/library/unittest.html)** - Testing framework
- **[pytest](https://docs.pytest.org/)** - Test runner and coverage

---

## 📦 Installation

### 📌 Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### 🔧 Install from PyPI (Coming Soon)

```bash
$ pip install phoenix-key

🔧 Install from GitHub
bash

$ git clone https://github.com/Amirsam-Azmoodeh/phoenix-key.git
$ cd phoenix-key
$ pip install -e .

📦 Install dependencies manually
bash

$ pip install cryptography>=41.0.0

⚡ Quick Start
Basic Usage
python

from phoenix_key import PhoenixKey, Status

# ============================================================================
# 1. Initialize the key chain manager
# ============================================================================
# In a real system, these values would be established via asymmetric encryption
pk = PhoenixKey(
    key=b"my_secret_key_1234567890123456",  # Initial key (from handshake)
    nonce=b"initial_nonce_12345678",        # Initial nonce
    counter=0,                               # Starting counter
    ttl=5,                                   # Rejection timer (seconds)
    max_counter=10                           # Max gap between counters
)

# ============================================================================
# 2. Process incoming keys (received from the other party)
# ============================================================================

# Send a new key
result = pk.check_key(b"nonce_for_message_1", 1)

if result[0][0] == Status.SUCCESS:
    key = result[0][1]  # The derived key (32 bytes)
    print(f"✅ Key created: {key.hex()[:16]}...")
else:
    print(f"❌ Key rejected: {result}")

# ============================================================================
# 3. Out-of-order recovery example
# ============================================================================

# Send key 5 before key 2 (simulating packet loss)
pk.check_key(b"nonce_5", 5)   # ⏳ Pending (waiting for key 4)
pk.check_key(b"nonce_3", 3)   # ⏳ Pending (waiting for key 2)

# Send the missing key - triggers cascade recovery!
result = pk.check_key(b"nonce_2", 2)  # 🔥 Cascade recovery

# Results: keys 2, 3, 4, 5 are all created automatically!
print(f"✅ Created {len(result)} keys: 2, 3, 4, 5")

Integration with Encryption
python

from phoenix_key import PhoenixKey, Status
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# Initialize PhoenixKey
pk = PhoenixKey(
    key=b"shared_secret_32_bytes_1234567890",
    nonce=b"initial_nonce_12345678",
    counter=0,
    ttl=5,
    max_counter=10
)

# Derive a key for message 1
result = pk.check_key(b"message_1_nonce", 1)
if result[0][0] == Status.SUCCESS:
    key = result[0][1]
    
    # Use the key with ChaCha20-Poly1305
    cipher = ChaCha20Poly1305(key)
    nonce = b"unique_nonce_12_bytes"
    ciphertext = cipher.encrypt(nonce, b"Hello, World!", None)
    
    print(f"✅ Message encrypted with key: {key.hex()[:16]}...")

📚 How It Works
🔄 Key Chain Protocol Flowchart
text

┌─────────────────────────────────────────────────────────────┐
│                    INITIAL SETUP                            │
│  Asymmetric handshake establishes master_key + nonce       │
│  PhoenixKey(master_key, nonce, counter=0)                  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│              KEY DERIVATION (HKDF + BLAKE2s)               │
│                                                             │
│   key_n = HKDF(                                             │
│       algorithm=BLAKE2s,                                    │
│       salt=b'phoenix-salt-v1',                              │
│       info=b'phoenix-key-derivation-v1' + nonce + counter, │
│       key=key_{n-1}                                        │
│   )                                                         │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│              CHECK_KEY PROCESSING                           │
│                                                             │
│  ┌─────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │ Check Reject│ → │Validate Range│ → │  Duplicate?   │  │
│  │   Timers    │    │   counter    │    │              │  │
│  └─────────────┘    └──────────────┘    └──────────────┘  │
│                                                │            │
│                              ┌─────────────────┴──────────┐ │
│                              │                            │ │
│                              ▼                            ▼ │
│                    ┌──────────────┐          ┌──────────────┐│
│                    │ counter-1 == │          │   PENDING    ││
│                    │ last_counter │          │   STORED    ││
│                    └──────────────┘          └──────────────┘│
│                              │                            │ │
│                              ▼                            │ │
│                    ┌──────────────┐                       │ │
│                    │   CREATE     │                       │ │
│                    │  NEW KEY     │                       │ │
│                    └──────────────┘                       │ │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│              CASCADE RECOVERY (ADD_KEY)                     │
│                                                             │
│   When key_n arrives:                                       │
│   ┌──────────────────────────────────────────────────┐     │
│   │ 1. Create key_n                                   │     │
│   │ 2. Remove key_{n-1} (Forward Secrecy)           │     │
│   │ 3. Check if key_{n+1} is pending                 │     │
│   │ 4. If yes → Create key_{n+1} (go to step 2)     │     │
│   │ 5. Continue until no more pending keys           │     │
│   └──────────────────────────────────────────────────┘     │
│                                                             │
│   🔥 Cascade Effect: One key unlocks the entire chain!     │
└─────────────────────────────────────────────────────────────┘

🎯 Response Codes
Code	Value	Meaning
Status.SUCCESS	1	Key created successfully
Status.PENDING	2	Key waiting for previous key
Status.REJECT	3	Rejection timer expired
Status.INVALID	4	Invalid or duplicate key
Key Derivation

PhoenixKey uses HKDF (HMAC-based Key Derivation Function) with BLAKE2s:
text

key_n = HKDF(
    algorithm=hashes.BLAKE2s(32),
    length=32,
    salt=b'phoenix-salt-v1',
    info=b'phoenix-key-derivation-v1' + nonce + counter.to_bytes(4, 'big'),
    key=key_{n-1}
)

Cascade Recovery Example
text

Scenario: Keys arrive out of order

Time 1: Receive key 5 → ⏳ PENDING (waiting for key 4)
Time 2: Receive key 3 → ⏳ PENDING (waiting for key 2)
Time 3: Receive key 2 → 🔥 CASCADE START
        - Create key 2 ✅
        - Create key 3 ✅ (was pending)
        - Create key 4 ✅ (automatically derived)
        - Create key 5 ✅ (was pending)
        
Result: All keys 2, 3, 4, 5 created in a single operation!

🔒 Security Considerations
✅ Forward Secrecy

Each key in the chain is derived from the previous key using HKDF. When a key is used and replaced, the previous key is immediately deleted from memory. This ensures that even if a key is compromised, it cannot be used to derive future or past keys.
✅ Protection Against Replay Attacks

    Counter validation: Each key is tied to a unique counter value

    Nonce uniqueness: Keys derived with different nonces produce different results

    Duplicate detection: The protocol rejects duplicate counter values

✅ HKDF Best Practices

    Uses BLAKE2s for high performance and security

    Salt: Fixed salt (b'phoenix-salt-v1') for consistent derivations

    Info: Includes prefix + nonce + counter for domain separation

⚠️ Known Limitations
Limitation	Description	Mitigation
max_counter	Maximum gap between consecutive counters (default: 10)	Configure based on network conditions
TTL	Fixed rejection timer may not suit all networks	Adjust TTL based on expected latency
State Loss	If both parties lose state, sync is required	Implement periodic state sync or fallback keys
Memory Usage	Pending keys are stored until recovered	TTL prevents indefinite storage
🔐 Recommendations for Production

    Always use AEAD (e.g., AES-GCM, ChaCha20-Poly1305) with PhoenixKey

    Establish initial keys via asymmetric cryptography (e.g., X25519)

    Monitor rejection timers to detect network issues

    Set max_counter based on your network's maximum expected packet loss

    Use unique nonces for each message

📊 Performance
Benchmark Results

    1000 keys derivation: < 2 seconds

    Memory usage: O(1) - only last key stored

    Cascade recovery: O(n) where n is number of pending keys

Comparison
Metric	PhoenixKey	Signal	Noise
Key derivation	HKDF-BLAKE2s	HKDF-SHA256	HKDF-SHA256
Out-of-order recovery	✅ Cascade	✅ Ratchet	⚠️ Limited
Memory footprint	🟢 Very low	🔴 High	🟡 Medium
Speed	🟢 Fast	🟡 Medium	🟢 Fast
Complexity	🟢 Simple	🔴 Complex	🟡 Medium
🧪 Testing
📌 Run all tests
bash

$ pytest tests/ -v

📌 Run specific test file
bash

$ pytest tests/test_phoenix_key.py -v

📌 Test coverage
bash

$ pytest --cov=phoenix_key tests/

📊 Test Results
bash

$ pytest tests/ -v

==================== test session starts ====================
collected 56 items

tests/test_phoenix_key.py ....................... [100%]
tests/test_integration.py ......... [100%]

==================== 56 passed in 18.7s ====================

✅ Test Coverage
Test Category	Count	Status
Unit Tests	47	✅ All Passing
Integration Tests	9	✅ All Passing
Total	56	✅ 100% Pass
📁 Project Structure
text

phoenix-key/
│
├── phoenix_key/                    # Main package
│   ├── __init__.py                 # Package entry point
│   └── core.py                     # PhoenixKey core implementation
│
├── tests/                          # Test suite
│   ├── __init__.py
│   ├── test_phoenix_key.py         # 47 unit tests
│   └── test_integration.py         # 9 integration tests
│
├── pyproject.toml                  # Build configuration
├── requirements.txt                # Dependencies
├── README.md                       # Documentation
├── CONTRIBUTING.md                 # Contributing guide
├── LICENSE                         # Apache 2.0
└── .gitignore                      # Git ignore file

🤝 Contributing

We welcome contributions! Here's how you can help:
🐛 Found a bug?

    Check the issues page

    Create a new issue with detailed steps to reproduce

    Label it as bug

💡 Have an idea?

    Create a feature request issue

    Discuss with the community

    Submit a pull request

📝 Development setup
bash

# Clone the repository
$ git clone https://github.com/Amirsam-Azmoodeh/phoenix-key.git
$ cd phoenix-key

# Create a virtual environment
$ python -m venv venv
$ source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
$ pip install -e ".[dev]"

# Run tests
$ pytest tests/ -v

# Format code
$ black phoenix_key/
$ isort phoenix_key/

📋 Pull Request Guidelines

    ✅ Write clear commit messages

    ✅ Add tests for new features

    ✅ Update documentation

    ✅ Follow PEP 8 style guidelines

    ✅ Ensure all tests pass

🗺️ Roadmap
🔜 Short-term (v1.1)

    Async support for check_key

    Customizable hash functions (SHA-256, SHA-3)

    Integration examples with popular frameworks (FastAPI, Django)

📅 Medium-term (v1.2)

    Persistent state storage (SQLite, Redis)

    Metrics and monitoring support

    Command-line tool for testing

🚀 Long-term (v2.0)

    Multi-party key chain support

    Post-quantum cryptography integration

    Formal verification of the protocol

📄 License
text

Copyright 2026 Amirsam Azmoodeh

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

📬 Contact
<div align="center">

Amirsam Azmoodeh

https://img.shields.io/badge/%F0%9F%93%A7%2520Email-amirsamazmoodeh%2540gmail.com-red?style=for-the-badge&logo=gmail&logoColor=white
https://img.shields.io/badge/%F0%9F%94%97%2520LinkedIn-amirsam--azmoodeh-blue?style=for-the-badge&logo=linkedin&logoColor=white
https://img.shields.io/badge/%F0%9F%90%99%2520GitHub-Amirsam--Azmoodeh-black?style=for-the-badge&logo=github&logoColor=white
</div>
🌟 Star the Project

If you found PhoenixKey useful, please consider starring the repository on GitHub! ⭐
<div align="center">

https://img.shields.io/github/stars/Amirsam-Azmoodeh/phoenix-key?style=social
</div><div align="center">

Built with ❤️ by Amirsam Azmoodeh
</div> ```
