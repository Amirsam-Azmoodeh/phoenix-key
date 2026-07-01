"""
PhoenixKey - A Secure Key Chain Management Protocol with Recovery Capability

This module implements a cryptographic key chain protocol where each key is derived
from the previous key using HKDF with BLAKE2s. It supports out-of-order recovery,
rejection handling with TTL timers, and automatic cascade recovery.

Example:
    >>> pk = PhoenixKey(b"master_key", b"initial_nonce", 0, ttl=5, max_counter=10)
    >>> result = pk.check_key(b"new_nonce", 1)
    >>> if result[0][0] == Status.SUCCESS:
    ...     key = result[0][1]  # Use this key for decryption
"""

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import time


class Status:
    """
    Response status codes for key chain operations.
    
    Attributes:
        SUCCESS (int): Key created successfully (1)
        PENDING (int): Key waiting for previous key (2)
        REJECT (int): Rejection timer expired (3)
        INVALID (int): Invalid or duplicate key (4)
    """
    SUCCESS = 1
    PENDING = 2
    REJECT = 3
    INVALID = 4


class PhoenixKey:
    """
    Key chain manager with out-of-order recovery and rejection handling.
    
    This class manages a chain of cryptographic keys where each key is derived from 
    the previous key, a nonce, and a counter value using HKDF with BLAKE2s.
    
    Features:
        - Sequential key generation using HKDF-BLAKE2s
        - Out-of-order key recovery (cascade effect)
        - Rejection handling with TTL (Time-To-Live) timers
        - Duplicate and out-of-range counter validation
        - Automatic cleanup of old keys
    
    Attributes:
        ttl (int): Time-To-Live for rejection timers in seconds
        max_counter (int): Maximum allowed gap between consecutive counters
        key_dict (dict): Stores key information {counter: [key, nonce, is_valid]}
        key_dict_reject (dict): Stores rejection timers {counter: expiry_time}
        last_counter (int): The most recently created valid counter
    """

    def __init__(self, key: bytes, nonce: bytes, counter: int, ttl: int, max_counter: int):
        """
        Initialize the key chain manager with the initial key.
        
        Args:
            key (bytes): Initial cryptographic key (from asymmetric handshake)
            nonce (bytes): Initial nonce value
            counter (int): Starting counter value
            ttl (int): Time-To-Live for rejection timers (seconds)
            max_counter (int): Maximum allowed gap between consecutive counters
            
        Example:
            >>> pk = PhoenixKey(
            ...     key=b"my_secret_key_1234567890123456",
            ...     nonce=b"initial_nonce_12345678",
            ...     counter=0,
            ...     ttl=5,
            ...     max_counter=10
            ... )
        """
        self.ttl = ttl
        self.max_counter = max_counter
        self.key_dict = {}
        self.key_dict_reject = {}
        
        # Create and store the initial key
        final_key = self._create_key(key, nonce, counter)
        self.key_dict[counter] = [final_key, nonce, True]
        self.last_counter = counter

    def _create_key(self, key: bytes, nonce: bytes, counter: int) -> bytes:
        """
        Generate a new key using HKDF with BLAKE2s.
        
        The key is derived from the previous key, a nonce, and the counter value.
        Uses HKDF standard with BLAKE2s for high performance and security.
        
        Args:
            key (bytes): Previous key in the chain
            nonce (bytes): Nonce value for this key
            counter (int): Counter value for this key
            
        Returns:
            bytes: Newly generated cryptographic key (32 bytes)
        """
        # Create HKDF instance with BLAKE2s
        hkdf = HKDF(
            algorithm=hashes.BLAKE2s(32),  # 32 = digest size
            length=32,                      # Output key length (256 bits)
            salt=b'phoenix-salt-v1',        # Consistent salt for all derivations
            info=b'phoenix-key-derivation-v1' + nonce + counter.to_bytes(4, 'big'),
            backend=default_backend()
        )
        
        # Derive the new key from the previous key
        return hkdf.derive(key)

    def _add_key(self, nonce: bytes, counter: int) -> list:
        """
        Create a new key and any pending keys that follow it.
        
        This method implements the "cascade recovery" effect:
        1. Creates the requested key using the previous key
        2. Removes the previous key if it was valid
        3. Recursively creates any pending keys that are waiting
        
        Args:
            nonce (bytes): Nonce value for the new key
            counter (int): Counter value for the new key
            
        Returns:
            list: List of created keys in format [[Status.SUCCESS, key], ...]
        """
        key_list = []
        
        # Check if the previous key exists and is valid
        if counter - 1 not in self.key_dict or self.key_dict[counter - 1][0] is None:
            # Previous key not available - mark this key as pending
            self.key_dict[counter] = [None, nonce, False]
            self.key_dict_reject[counter - 1] = time.time() + self.ttl
            return [[Status.PENDING, counter]]
        
        # Create the requested key using the previous key
        final_key = self._create_key(
            self.key_dict[counter - 1][0],
            nonce,
            counter
        )
        self.key_dict[counter] = [final_key, nonce, True]
        
        # Remove previous key if it was valid (not pending)
        if counter - 1 in self.key_dict and self.key_dict[counter - 1][2]:
            del self.key_dict[counter - 1]
        
        # Update last counter
        self.last_counter = counter
        key_list.append([Status.SUCCESS, final_key])
        
        # Build any pending keys that are waiting in sequence (cascade effect)
        next_counter = counter + 1
        while next_counter in self.key_dict:
            pending_nonce = self.key_dict[next_counter][1]
            
            # Check if the previous key exists and is valid
            if (next_counter - 1 not in self.key_dict or 
                self.key_dict[next_counter - 1][0] is None):
                break  # Stop cascade if a key is missing
            
            # Create the pending key
            key = self._create_key(
                self.key_dict[next_counter - 1][0],
                pending_nonce,
                next_counter
            )
            self.key_dict[next_counter] = [key, pending_nonce, True]
            self.last_counter = next_counter
            key_list.append([Status.SUCCESS, key])
            
            # Clean up the previous key if it was valid
            if next_counter - 1 in self.key_dict and self.key_dict[next_counter - 1][2]:
                del self.key_dict[next_counter - 1]
            
            next_counter += 1
        
        return key_list

    def check_key(self, nonce: bytes, counter: int) -> list:
        """
        Process an incoming key request - the main entry point.
        
        This method handles the complete key validation and creation logic:
        1. Check for expired rejection timers
        2. Validate counter range (not too small, not beyond max_counter)
        3. Check for duplicate counters
        4. Handle out-of-order keys (pending state)
        5. Create new keys when the previous key is available
        
        Args:
            nonce (bytes): Nonce extracted from the ciphertext
            counter (int): Counter value from the ciphertext
            
        Returns:
            list: Response messages in format:
                - [Status.SUCCESS, key] for successful key creation
                - [Status.PENDING, counter] for pending key (waiting for previous key)
                - [Status.REJECT, counter] for rejection request (timer expired)
                - [Status.INVALID, counter] for invalid/rejected key
        """
        # Step 1: Check and process any expired rejection timers
        reject_list = self._check_rejections()
        
        # Step 2: Validate counter range
        if (self.last_counter > counter) or (self.last_counter + self.max_counter < counter):
            if reject_list:
                return reject_list + [[Status.INVALID, counter]]
            return [Status.INVALID, counter]
        
        # Step 3: Check if this counter already exists
        if counter in self.key_dict:
            if self.key_dict[counter][2] is True:
                # Duplicate valid key - reject
                if reject_list:
                    return reject_list + [[Status.INVALID, counter]]
                return [Status.INVALID, counter]
            else:
                # Key is in pending state - update nonce and refresh timer
                self.key_dict[counter] = [None, nonce, False]
                self.key_dict_reject[counter - 1] = time.time() + self.ttl
                if reject_list:
                    return reject_list + [[Status.PENDING, counter]]
                return [Status.PENDING, counter]
        
        # Step 4: If previous key is available, create the new key chain
        if counter - 1 == self.last_counter:
            result = self._add_key(nonce, counter)
            if reject_list:
                return reject_list + result
            return result
        
        # Step 5: Otherwise, put this key in pending state
        self.key_dict[counter] = [None, nonce, False]
        self.key_dict_reject[counter - 1] = time.time() + self.ttl
        if reject_list:
            return reject_list + [[Status.PENDING, counter]]
        return [Status.PENDING, counter]

    def _check_rejections(self) -> list:
        """
        Check and process expired rejection timers.
        
        Iterates through all stored rejection timers and removes any that have expired.
        Expired timers generate rejection requests.
        
        Returns:
            list: List of expired rejection requests in format [[Status.REJECT, counter], ...]
        """
        now = time.time()
        reject_list = []
        
        for rejected_counter in list(self.key_dict_reject.keys()):
            if now > self.key_dict_reject[rejected_counter]:
                reject_list.append([Status.REJECT, rejected_counter])
                del self.key_dict_reject[rejected_counter]
        
        return reject_list

    # ==================== Legacy Methods (Backward Compatibility) ====================
    
    def create_key(self, key: bytes, nonce: bytes, counter: int) -> bytes:
        """
        Legacy method - use _create_key instead.
        
        Kept for backward compatibility with existing code.
        """
        return self._create_key(key, nonce, counter)

    def add_key(self, nonce: bytes, counter: int) -> list:
        """
        Legacy method - use _add_key instead.
        
        Kept for backward compatibility with existing code.
        """
        return self._add_key(nonce, counter)

    def reject(self) -> list:
        """
        Legacy method - use _check_rejections instead.
        
        Kept for backward compatibility with existing code.
        """
        return self._check_rejections()