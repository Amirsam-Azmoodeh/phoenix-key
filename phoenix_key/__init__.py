"""
PhoenixKey - A Secure Key Chain Management Protocol with Recovery Capability

A lightweight key chain management protocol with out-of-order recovery,
cascade recovery, and TTL rejection handling.

Example:
    >>> from phoenix_key import PhoenixKey, Status
    >>> 
    >>> pk = PhoenixKey(
    ...     key=b"my_secret_key_1234567890123456",
    ...     nonce=b"initial_nonce_12345678",
    ...     counter=0,
    ...     ttl=5,
    ...     max_counter=10
    ... )
    >>> 
    >>> result = pk.check_key(b"nonce_for_message_1", 1)
    >>> if result[0][0] == Status.SUCCESS:
    ...     key = result[0][1]
    ...     print(f"✅ Key created: {key.hex()[:16]}...")
"""

from .core import PhoenixKey, Status

__version__ = "1.0.0"
__all__ = ["PhoenixKey", "Status"]
__author__ = "Amirsam Azmoodeh"
__email__ = "amirsamazmoodeh@gmail.com"
__license__ = "Apache-2.0"
