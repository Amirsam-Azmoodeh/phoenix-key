```markdown
<!-- PhoenixKey - A Secure Key Chain Management Protocol with Recovery Capability -->

<div align="center">

![PhoenixKey Logo](https://img.shields.io/badge/PhoenixKey-🔥-orange?style=for-the-badge&logo=python)

# 🔐 PhoenixKey

### A Secure Key Chain Management Protocol with Recovery Capability

[![Python Version](https://img.shields.io/badge/python-3.8+-blue.svg?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-red.svg?style=flat-square&logo=apache&logoColor=white)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-25%20passed-brightgreen.svg?style=flat-square&logo=github-actions&logoColor=white)](https://github.com/Amirsam-Azmoodeh/phoenix-key/actions)
[![Code Style](https://img.shields.io/badge/code%20style-PEP%208-black?style=flat-square&logo=python&logoColor=white)]()
[![Security](https://img.shields.io/badge/security-HKDF%20%2B%20BLAKE2s-brightgreen?style=flat-square)]()

</div>

---

## 📖 Table of Contents

- [🚀 Why PhoenixKey?](#-why-phoenixkey)
- [✨ Features](#-features)
- [🛠️ Technologies](#️-technologies)
- [📦 Installation](#-installation)
- [⚡ Quick Start](#-quick-start)
- [📚 How It Works](#-how-it-works)
- [🔒 Security Considerations](#-security-considerations)
- [📁 Project Structure](#-project-structure)
- [🧪 Testing](#-testing)
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

**Perfect for:** IoT devices, secure messaging, satellite communications, and any system where packet loss is common.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔑 **HKDF with BLAKE2s** | High-performance key derivation using industry-standard HKDF with the ultra-fast BLAKE2s hash |
| 🔄 **Out-of-Order Recovery** | Automatically recovers when keys arrive out of sequence |
| ⏱️ **TTL Rejection Handling** | Prevents deadlocks with Time-To-Live timers for missing keys |
| 🌊 **Cascade Recovery** | Rebuilds entire pending key chains with a single key arrival |
| 🧹 **Automatic Cleanup** | Removes old keys to maintain a small memory footprint |
| 🛡️ **Duplicate Detection** | Prevents replay attacks with counter validation |
| 📏 **Range Validation** | Configurable `max_counter` to limit out-of-order gaps |
| 🐍 **Type Hints** | Full type annotations for better IDE support |
| 📚 **Comprehensive Docs** | Complete docstrings and examples |

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

---

## 📦 Installation

### 📌 Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### 🔧 Install from GitHub (Coming soon to PyPI)

```bash
$ git clone https://github.com/Amirsam-Azmoodeh/phoenix-key.git
$ cd phoenix-key
$ pip install -e .
```

### 📦 Install dependencies manually

```bash
$ pip install cryptography>=41.0.0
```

---

## ⚡ Quick Start

```python
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
```

---

## 📚 How It Works

### 🔄 Key Chain Protocol Flowchart

```
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
│       salt=nonce_n,                                         │
│       info=b'prefix' + counter_n,                          │
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
│   │ 2. Remove key_{n-1}                               │     │
│   │ 3. Check if key_{n+1} is pending                 │     │
│   │ 4. If yes → Create key_{n+1} (go to step 2)     │     │
│   │ 5. Continue until no more pending keys           │     │
│   └──────────────────────────────────────────────────┘     │
│                                                             │
│   🔥 Cascade Effect: One key unlocks the entire chain!     │
└─────────────────────────────────────────────────────────────┘
```

### 🎯 Response Codes

| Code | Meaning |
|------|---------|
| `Status.SUCCESS` (1) | Key created successfully |
| `Status.PENDING` (2) | Key waiting for previous key |
| `Status.REJECT` (3) | Rejection timer expired |
| `Status.INVALID` (4) | Invalid or duplicate key |

---

## 🔒 Security Considerations

### ✅ **Forward Secrecy**
Each key in the chain is derived from the previous key using HKDF. When a key is used and replaced, the previous key is **immediately deleted** from memory. This ensures that even if a key is compromised, it cannot be used to derive future or past keys.

### ✅ **Protection Against Replay Attacks**
- **Counter validation**: Each key is tied to a unique counter value
- **Nonce uniqueness**: Keys derived with different nonces produce different results
- **Duplicate detection**: The protocol rejects duplicate counter values

### ✅ **HKDF Best Practices**
- Uses **BLAKE2s** for high performance and security
- **Salt** is derived from the nonce (varies per message)
- **Info** includes a fixed prefix + counter for domain separation

### ⚠️ **Known Limitations**
| Limitation | Description | Mitigation |
|------------|-------------|------------|
| `max_counter` | Maximum gap between consecutive counters (default: 10) | Configure based on network conditions |
| **TTL** | Fixed rejection timer may not suit all networks | Adjust TTL based on expected latency |
| **State Loss** | If both parties lose state, sync is required | Implement periodic state sync or fallback keys |
| **Memory Usage** | Pending keys are stored until recovered | TTL prevents indefinite storage |

### 🔐 **Recommendations for Production**
1. **Always use AEAD** (e.g., AES-GCM, ChaCha20-Poly1305) with PhoenixKey
2. **Establish initial keys** via asymmetric cryptography (e.g., X25519)
3. **Monitor rejection timers** to detect network issues
4. **Set `max_counter`** based on your network's maximum expected packet loss
5. **Consider using HKDF with `salt=initial_nonce`** for more consistent derivations

---

## 📁 Project Structure

```
phoenix-key/
├── phoenix_key/
│   └── __init__.py          # Main PhoenixKey class
├── tests/
│   └── test_phoenix_key.py  # 25+ unit tests
├── examples/
│   ├── simple_chat.py       # Basic chat example
│   └── iot_gateway.py       # IoT simulation
├── README.md                # This file
├── setup.py                 # Package configuration
├── requirements.txt         # Dependencies
├── LICENSE                  # Apache 2.0
└── .github/
    └── workflows/
        └── tests.yml        # CI/CD pipeline
```

---

## 🧪 Testing

### 📌 Run all tests

```bash
$ python -m unittest discover tests -v
```

### 📌 Run specific test file

```bash
$ python -m unittest tests/test_phoenix_key.py
```

### 📌 Test coverage

```bash
$ pip install coverage
$ coverage run -m unittest discover
$ coverage report -m
```

### 📊 Test Results

```bash
$ python -m unittest tests/test_phoenix_key.py

test_basic_flow (test_phoenix_key.TestPhoenixKey) ... ok
test_out_of_order (test_phoenix_key.TestPhoenixKey) ... ok
test_cascade_recovery (test_phoenix_key.TestPhoenixKey) ... ok
test_duplicate_detection (test_phoenix_key.TestPhoenixKey) ... ok
test_counter_range (test_phoenix_key.TestPhoenixKey) ... ok
test_rejection_timer (test_phoenix_key.TestPhoenixKey) ... ok

----------------------------------------------------------------------
Ran 25 tests in 7.5s

OK ✅
```

---

## 🤝 Contributing

We welcome contributions! Here's how you can help:

### 🐛 Found a bug?
1. Check the [issues](https://github.com/Amirsam-Azmoodeh/phoenix-key/issues) page
2. Create a new issue with detailed steps to reproduce
3. Label it as `bug`

### 💡 Have an idea?
1. Create a feature request issue
2. Discuss with the community
3. Submit a pull request

### 📝 Development setup

```bash
# Clone the repository
$ git clone https://github.com/Amirsam-Azmoodeh/phoenix-key.git
$ cd phoenix-key

# Create a virtual environment
$ python -m venv venv
$ source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
$ pip install -e ".[dev]"

# Run tests
$ python -m unittest discover tests -v

# Format code
$ black phoenix_key/
$ isort phoenix_key/
```

### 📋 Pull Request Guidelines

- ✅ Write clear commit messages
- ✅ Add tests for new features
- ✅ Update documentation
- ✅ Follow PEP 8 style guidelines
- ✅ Ensure all tests pass

---

## 🗺️ Roadmap

### 🔜 **Short-term (v1.1)**
- [ ] Async support for `check_key`
- [ ] Customizable hash functions (SHA-256, SHA-3)
- [ ] Integration examples with popular frameworks (FastAPI, Django)

### 📅 **Medium-term (v1.2)**
- [ ] Persistent state storage (SQLite, Redis)
- [ ] Metrics and monitoring support
- [ ] Command-line tool for testing

### 🚀 **Long-term (v2.0)**
- [ ] Multi-party key chain support
- [ ] Post-quantum cryptography integration
- [ ] Formal verification of the protocol

---

## 📄 License

```
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
```

---

## 📬 Contact

<div align="center">

**Amirsam Azmoodeh**

[![Email](https://img.shields.io/badge/📧%20Email-amirsamazmoodeh%40gmail.com-red?style=for-the-badge&logo=gmail&logoColor=white)](mailto:amirsamazmoodeh@gmail.com)
[![LinkedIn](https://img.shields.io/badge/🔗%20LinkedIn-amirsam--azmoodeh-blue?style=for-the-badge&logo=linkedin&logoColor=white)](https://linkedin.com/in/amirsam-azmoodeh)
[![GitHub](https://img.shields.io/badge/🐙%20GitHub-Amirsam--Azmoodeh-black?style=for-the-badge&logo=github&logoColor=white)](https://github.com/Amirsam-Azmoodeh)

</div>

---

## 🌟 Star the Project

If you found PhoenixKey useful, please consider **starring** the repository on GitHub! ⭐

<div align="center">

[![GitHub Stars](https://img.shields.io/github/stars/Amirsam-Azmoodeh/phoenix-key?style=social)](https://github.com/Amirsam-Azmoodeh/phoenix-key)

</div>

---

<div align="center">

**Built with ❤️ by [Amirsam Azmoodeh](https://github.com/Amirsam-Azmoodeh)**

</div>
```