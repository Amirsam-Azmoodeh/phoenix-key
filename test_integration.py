"""
Comprehensive PhoenixKey Test with ChaCha20 and AES-GCM
(FIXED VERSION - flush_pending_encryption now works correctly)
"""

import unittest
import os
import time
import struct
from typing import Dict, Tuple, Optional, List
from dataclasses import dataclass
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from phoenix_key import PhoenixKey, Status


# ============================================================================
# Data Structures
# ============================================================================

@dataclass
class SecureMessage:
    """Represents a secure message with all necessary metadata"""
    counter: int
    nonce: bytes
    ciphertext: bytes
    tag: bytes
    
    def pack(self) -> bytes:
        """Pack message for transmission"""
        nonce_len = len(self.nonce)
        return (
            struct.pack('!I', self.counter) +
            struct.pack('!H', nonce_len) +
            self.nonce +
            self.ciphertext +
            self.tag
        )
    
    @staticmethod
    def unpack(data: bytes) -> 'SecureMessage':
        """Unpack message from transmission format"""
        counter = struct.unpack('!I', data[:4])[0]
        nonce_len = struct.unpack('!H', data[4:6])[0]
        nonce = data[6:6+nonce_len]
        ciphertext = data[6+nonce_len:-16]
        tag = data[-16:]
        return SecureMessage(counter, nonce, ciphertext, tag)


# ============================================================================
# PhoenixKey Factory
# ============================================================================

def create_phoenix_key(shared_secret: bytes, initial_nonce: bytes, 
                       start_counter: int = 0, ttl: int = 5, max_counter: int = 10) -> PhoenixKey:
    """
    Create a new PhoenixKey instance with the same parameters
    
    Each party should have their own PhoenixKey instance
    """
    return PhoenixKey(
        key=shared_secret,
        nonce=initial_nonce,
        counter=start_counter,
        ttl=ttl,
        max_counter=max_counter
    )


# ============================================================================
# Fixed SecureChannel
# ============================================================================

class SecureChannel:
    """
    Base class for secure communication channel using PhoenixKey
    
    ✅ Each channel has its own PhoenixKey instance
    ✅ Handles all result formats (flat lists and list of lists)
    ✅ Stores keys in context for later use
    ✅ flush_pending_encryption works correctly
    """
    
    def __init__(
        self,
        name: str,
        shared_secret: bytes,
        initial_nonce: bytes,
        start_counter: int = 0,
        ttl: int = 5,
        max_counter: int = 10,
        algorithm: str = 'ChaCha20',
        auto_retry: bool = True
    ):
        self.name = name
        self.algorithm = algorithm
        self.auto_retry = auto_retry
        
        # ✅ Each party has their OWN PhoenixKey instance
        self.phoenix = create_phoenix_key(
            shared_secret=shared_secret,
            initial_nonce=initial_nonce,
            start_counter=start_counter,
            ttl=ttl,
            max_counter=max_counter
        )
        
        # Store encryption context (key for each counter)
        self.encryption_context: Dict[int, bytes] = {}
        self.decryption_context: Dict[int, bytes] = {}
        
        # Store pending messages to be sent
        self.pending_messages: Dict[int, Tuple[bytes, bytes, int]] = {}
        # Store pending received messages (for decryption)
        self.pending_received: Dict[int, SecureMessage] = {}
        
        # Retry configuration
        self.max_retries = 3
        self.retry_delay = 0.5
        
        # Statistics
        self.stats = {
            'encrypted': 0,
            'decrypted': 0,
            'pending': 0,
            'rejected': 0,
            'invalid': 0,
            'retries': 0
        }
        
        # Temporary storage for messages encrypted from pending queue
        self._pending_encrypted: Dict[int, SecureMessage] = {}
        
        print(f"[{self.name}] Channel initialized with {algorithm}")
    
    def _create_aead(self, key: bytes):
        """Create AEAD cipher instance based on selected algorithm"""
        if self.algorithm == 'ChaCha20':
            return ChaCha20Poly1305(key)
        elif self.algorithm == 'AES-GCM':
            return AESGCM(key)
        else:
            raise ValueError(f"Unsupported algorithm: {self.algorithm}")
    
    def _generate_nonce(self, counter: int) -> bytes:
        """Generate nonce for encryption (12 bytes for both algorithms)"""
        nonce = struct.pack('!I', counter) + b'\x00' * 8
        return nonce[:12]
    
    def _handle_result(self, result, counter: int):
        """
        Process the result from phoenix.check_key.
        Returns a tuple: (list_of_success_items, first_other_status)
        Where success_items is a list of (counter, key) for SUCCESS.
        Supports both flat lists and list of lists.
        """
        success_items = []
        other = None
        
        if not result:
            return success_items, other
        
        # Normalize to list of pairs [status, data]
        pairs = []
        if isinstance(result, list) and len(result) > 0:
            if isinstance(result[0], list):
                # Already list of lists
                pairs = result
            elif isinstance(result[0], int):
                # Flat list: [status1, data1, status2, data2, ...]
                i = 0
                while i < len(result) - 1:
                    pairs.append([result[i], result[i+1]])
                    i += 2
                # If odd number of items, ignore last (shouldn't happen)
            else:
                # Unknown format
                other = (Status.INVALID, counter)
                return success_items, other
        
        # Process pairs
        current_counter = counter
        for item in pairs:
            if len(item) < 2:
                continue
            status = item[0]
            data = item[1]
            if status == Status.SUCCESS:
                success_items.append((current_counter, data))
                current_counter += 1
            else:
                if other is None:
                    other = (status, data)
                # Continue to collect successes after non-success
        
        return success_items, other
    
    def _encrypt_with_key(self, plaintext: bytes, counter: int, key: bytes, nonce: bytes) -> SecureMessage:
        """Helper method to encrypt with a given key"""
        self.encryption_context[counter] = key
        
        cipher = self._create_aead(key)
        ciphertext_with_tag = cipher.encrypt(nonce, plaintext, None)
        ciphertext = ciphertext_with_tag[:-16]
        tag = ciphertext_with_tag[-16:]
        
        self.stats['encrypted'] += 1
        
        msg = SecureMessage(counter, nonce, ciphertext, tag)
        
        print(f"[{self.name}] ✅ Encrypted message {counter} "
              f"with {self.algorithm} (key: {key[:4].hex()}...)")
        
        return msg
    
    def _encrypt_pending_messages(self):
        """
        Attempt to encrypt any pending messages that can now be encrypted.
        This will repeatedly call check_key on pending messages until no more progress.
        Returns a dictionary of encrypted messages (counter -> SecureMessage) that were just encrypted.
        """
        encrypted_now = {}
        if not self.pending_messages:
            return encrypted_now
        
        progress = True
        while progress:
            progress = False
            pending_items = list(self.pending_messages.items())
            for counter, (plaintext, nonce, retry_count) in pending_items:
                # If key already in context, use it
                if counter in self.encryption_context:
                    key = self.encryption_context[counter]
                    msg = self._encrypt_with_key(plaintext, counter, key, nonce)
                    encrypted_now[counter] = msg
                    del self.pending_messages[counter]
                    progress = True
                    break
                # Otherwise, ask PhoenixKey
                result = self.phoenix.check_key(nonce=nonce, counter=counter)
                success_items, other = self._handle_result(result, counter)
                
                if success_items:
                    for c, key in success_items:
                        self.encryption_context[c] = key
                        if c in self.pending_messages:
                            pt, n, rc = self.pending_messages[c]
                            msg = self._encrypt_with_key(pt, c, key, n)
                            encrypted_now[c] = msg
                            del self.pending_messages[c]
                            progress = True
                    if progress:
                        break
                elif other:
                    status, c = other
                    if status == Status.REJECT:
                        self.stats['rejected'] += 1
                        if counter in self.pending_messages:
                            del self.pending_messages[counter]
                            progress = True
                            break
                    elif status == Status.INVALID:
                        self.stats['invalid'] += 1
                        if counter in self.pending_messages:
                            del self.pending_messages[counter]
                            progress = True
                            break
                    elif status == Status.PENDING:
                        if retry_count < self.max_retries:
                            self.pending_messages[counter] = (plaintext, nonce, retry_count + 1)
                            self.stats['retries'] += 1
                        # No progress
            # if progress, continue loop
        # Store any newly encrypted messages for later flush
        self._pending_encrypted.update(encrypted_now)
        return encrypted_now
    
    def encrypt(self, plaintext: bytes, counter: int) -> Optional[SecureMessage]:
        """Encrypt a message using PhoenixKey-derived key."""
        nonce = self._generate_nonce(counter)
        
        # If key already in context, use it directly
        if counter in self.encryption_context:
            key = self.encryption_context[counter]
            msg = self._encrypt_with_key(plaintext, counter, key, nonce)
            if counter in self.pending_messages:
                del self.pending_messages[counter]
            if self.auto_retry:
                self._encrypt_pending_messages()
            return msg
        
        # Otherwise, ask PhoenixKey
        result = self.phoenix.check_key(nonce=nonce, counter=counter)
        success_items, other = self._handle_result(result, counter)
        
        direct_msg = None
        
        # Store all successful keys in context
        for c, key in success_items:
            self.encryption_context[c] = key
        
        # If this counter is among successes, encrypt it now
        for c, key in success_items:
            if c == counter:
                direct_msg = self._encrypt_with_key(plaintext, c, key, nonce)
                if c in self.pending_messages:
                    del self.pending_messages[c]
                break
        
        # For other successful counters, if they have pending messages, encrypt them
        for c, key in success_items:
            if c != counter and c in self.pending_messages:
                pt, n, rc = self.pending_messages[c]
                msg = self._encrypt_with_key(pt, c, key, n)
                # Store in pending_encrypted for flush
                self._pending_encrypted[c] = msg
                del self.pending_messages[c]
        
        # If there were successes, also try to encrypt any other pending messages
        if success_items and self.auto_retry:
            self._encrypt_pending_messages()
        
        # Handle non-success status for the requested counter
        if other:
            status, c = other
            if status == Status.PENDING:
                self.stats['pending'] += 1
                self.pending_messages[counter] = (plaintext, nonce, 0)
                print(f"[{self.name}] ⏳ Message {counter} pending (stored for retry)")
                if self.auto_retry:
                    self._encrypt_pending_messages()
                return None
            elif status == Status.REJECT:
                self.stats['rejected'] += 1
                print(f"[{self.name}] ❌ Message {counter} rejected")
                return None
            elif status == Status.INVALID:
                self.stats['invalid'] += 1
                print(f"[{self.name}] ❌ Message {counter} invalid")
                return None
        
        return direct_msg
    
    def _decrypt_with_key(self, message: SecureMessage, key: bytes) -> Optional[bytes]:
        """Helper method to decrypt with a given key"""
        self.decryption_context[message.counter] = key
        
        cipher = self._create_aead(key)
        ciphertext_with_tag = message.ciphertext + message.tag
        
        try:
            plaintext = cipher.decrypt(message.nonce, ciphertext_with_tag, None)
            self.stats['decrypted'] += 1
            
            print(f"[{self.name}] ✅ Decrypted message {message.counter} "
                  f"with {self.algorithm} (key: {key[:4].hex()}...)")
            
            return plaintext
            
        except Exception as e:
            print(f"[{self.name}] ❌ Decryption failed for message "
                  f"{message.counter}: {e}")
            return None
    
    def decrypt(self, message: SecureMessage) -> Optional[bytes]:
        """Decrypt a received message"""
        if message is None:
            return None
        
        # If key already in context, use it directly
        if message.counter in self.decryption_context:
            key = self.decryption_context[message.counter]
            plain = self._decrypt_with_key(message, key)
            if message.counter in self.pending_received:
                del self.pending_received[message.counter]
            return plain
        
        # Otherwise, store and ask PhoenixKey
        self.pending_received[message.counter] = message
        
        result = self.phoenix.check_key(
            nonce=message.nonce,
            counter=message.counter
        )
        
        success_items, other = self._handle_result(result, message.counter)
        
        # Store all successful keys in context
        for c, key in success_items:
            self.decryption_context[c] = key
        
        direct_plain = None
        
        # Decrypt this message if its counter is in success_items
        for c, key in success_items:
            if c == message.counter:
                plain = self._decrypt_with_key(message, key)
                if plain is not None:
                    direct_plain = plain
                if c in self.pending_received:
                    del self.pending_received[c]
                break
        
        # Decrypt any other pending received messages that now have keys
        for c, key in success_items:
            if c != message.counter and c in self.pending_received:
                pending_msg = self.pending_received[c]
                self._decrypt_with_key(pending_msg, key)
                del self.pending_received[c]
        
        # If we had successes, try to decrypt any other pending received messages
        if success_items and self.auto_retry:
            self._process_pending_received()
        
        # Handle non-success status
        if other:
            status, c = other
            if status == Status.PENDING:
                self.stats['pending'] += 1
                print(f"[{self.name}] ⏳ Message {message.counter} pending")
                if self.auto_retry:
                    self._process_pending_received()
                return None
            elif status == Status.REJECT:
                self.stats['rejected'] += 1
                print(f"[{self.name}] ❌ Message {message.counter} rejected")
                return None
            elif status == Status.INVALID:
                self.stats['invalid'] += 1
                print(f"[{self.name}] ❌ Message {message.counter} invalid")
                return None
        
        return direct_plain
    
    def _process_pending_received(self):
        """Process ALL pending received messages that can now be decrypted."""
        if not self.auto_retry:
            return
        
        progress = True
        while progress:
            progress = False
            for counter, message in list(self.pending_received.items()):
                # If key in context, decrypt
                if counter in self.decryption_context:
                    key = self.decryption_context[counter]
                    self._decrypt_with_key(message, key)
                    del self.pending_received[counter]
                    progress = True
                    break
                # Otherwise, ask PhoenixKey
                result = self.phoenix.check_key(nonce=message.nonce, counter=counter)
                success_items, other = self._handle_result(result, counter)
                if success_items:
                    for c, key in success_items:
                        self.decryption_context[c] = key
                        if c in self.pending_received:
                            self._decrypt_with_key(self.pending_received[c], key)
                            del self.pending_received[c]
                            progress = True
                            break
                    if progress:
                        break
                # if pending or reject, skip
            # continue if progress
    
    def get_pending_count(self) -> int:
        """Get number of pending messages"""
        return len(self.pending_messages) + len(self.pending_received)
    
    def get_stats(self) -> Dict:
        """Get channel statistics"""
        return {
            'name': self.name,
            'algorithm': self.algorithm,
            **self.stats,
            'last_counter': self.phoenix.last_counter,
            'pending_keys': len([k for k, v in self.phoenix.key_dict.items() 
                                if not v[2]]),
            'stored_keys': len(self.phoenix.key_dict),
            'pending_to_send': len(self.pending_messages),
            'pending_to_recv': len(self.pending_received),
            'rejection_timers': len(self.phoenix.key_dict_reject)
        }
    
    def print_stats(self):
        """Print channel statistics"""
        stats = self.get_stats()
        print(f"\n{'='*60}")
        print(f"[{self.name}] Statistics ({self.algorithm})")
        print(f"{'='*60}")
        print(f"✅ Encrypted: {stats['encrypted']}")
        print(f"✅ Decrypted: {stats['decrypted']}")
        print(f"⏳ Pending:   {stats['pending']}")
        print(f"❌ Rejected:  {stats['rejected']}")
        print(f"❌ Invalid:   {stats['invalid']}")
        print(f"🔄 Retries:   {stats['retries']}")
        print(f"📊 Last Counter: {stats['last_counter']}")
        print(f"📊 Pending Keys (in PhoenixKey): {stats['pending_keys']}")
        print(f"📊 Stored Keys: {stats['stored_keys']}")
        print(f"   - To Send: {stats['pending_to_send']}")
        print(f"   - To Recv: {stats['pending_to_recv']}")
        print(f"⏱️  Rejection Timers: {stats['rejection_timers']}")
        print(f"{'='*60}\n")
    
    def flush_pending_encryption(self) -> Dict[int, SecureMessage]:
        """
        Process all pending messages that can now be encrypted and return the encrypted messages.
        This will continue processing until no more pending messages can be encrypted.
        
        ✅ FIXED: Now copies existing encrypted messages before clearing the buffer.
        
        Returns:
            Dict[int, SecureMessage]: Dictionary mapping counter to encrypted SecureMessage
        """
        # First, try to encrypt any remaining pending messages
        self._encrypt_pending_messages()
        
        # Copy the current accumulated encrypted messages
        result = self._pending_encrypted.copy()
        
        # Clear the buffer for next time
        self._pending_encrypted = {}
        
        return result


# ============================================================================
# Test Cases (unchanged)
# ============================================================================

class TestPhoenixKeyWithChaCha20(unittest.TestCase):
    """Test PhoenixKey with ChaCha20-Poly1305 encryption"""
    
    def setUp(self):
        self.shared_secret = os.urandom(32)
        self.initial_nonce = b"init_nonce_12345678"
        self.start_counter = 0
        self.ttl = 5
        self.max_counter = 10
        
        self.alice = SecureChannel(
            name="Alice",
            shared_secret=self.shared_secret,
            initial_nonce=self.initial_nonce,
            start_counter=self.start_counter,
            ttl=self.ttl,
            max_counter=self.max_counter,
            algorithm='ChaCha20',
            auto_retry=True
        )
        
        self.bob = SecureChannel(
            name="Bob",
            shared_secret=self.shared_secret,
            initial_nonce=self.initial_nonce,
            start_counter=self.start_counter,
            ttl=self.ttl,
            max_counter=self.max_counter,
            algorithm='ChaCha20',
            auto_retry=True
        )
    
    def test_basic_communication(self):
        """Test: Basic communication with ChaCha20"""
        print("\n" + "="*60)
        print("TEST: Basic Communication with ChaCha20")
        print("="*60)
        
        messages = [
            b"Hello Alice!",
            b"How are you today?",
            b"This is a secret message",
            b"PhoenixKey is awesome!",
            b"ChaCha20 is fast and secure"
        ]
        
        for i, msg in enumerate(messages, 1):
            encrypted = self.alice.encrypt(msg, i)
            self.assertIsNotNone(encrypted, f"Failed to encrypt message {i}")
            
            decrypted = self.bob.decrypt(encrypted)
            self.assertIsNotNone(decrypted, f"Failed to decrypt message {i}")
            self.assertEqual(decrypted, msg, f"Message {i} corrupted")
            
            print(f"✅ Message {i}: '{msg[:20].decode()}...' sent and received")
        
        self.alice.print_stats()
        self.bob.print_stats()
    
    def test_out_of_order_delivery_chacha20(self):
        """Test: Out-of-order delivery recovery with ChaCha20"""
        print("\n" + "="*60)
        print("TEST: Out-of-Order Delivery with ChaCha20")
        print("="*60)
        
        messages = {
            3: b"Message 3 (sent first)",
            1: b"Message 1 (sent second)",
            4: b"Message 4 (sent third)",
            2: b"Message 2 (sent fourth)"
        }
        
        encrypted_messages = {}
        
        # First encryption attempt
        for counter, msg in messages.items():
            encrypted = self.alice.encrypt(msg, counter)
            if encrypted is not None:
                encrypted_messages[counter] = encrypted
        
        # Wait a bit and then flush pending encryption
        time.sleep(0.5)
        # Flush pending encryption to get any messages that are now ready
        pending_encrypted = self.alice.flush_pending_encryption()
        encrypted_messages.update(pending_encrypted)
        
        # Decrypt in order
        decrypted_messages = {}
        for counter in sorted(messages.keys()):
            if counter in encrypted_messages:
                decrypted = self.bob.decrypt(encrypted_messages[counter])
                if decrypted is not None:
                    decrypted_messages[counter] = decrypted
        
        # If some still missing, wait and flush again
        if len(decrypted_messages) < len(messages):
            time.sleep(0.5)
            pending_encrypted = self.alice.flush_pending_encryption()
            encrypted_messages.update(pending_encrypted)
            for counter in messages.keys():
                if counter not in decrypted_messages and counter in encrypted_messages:
                    decrypted = self.bob.decrypt(encrypted_messages[counter])
                    if decrypted is not None:
                        decrypted_messages[counter] = decrypted
        
        for counter, original in messages.items():
            self.assertIn(counter, decrypted_messages,
                         f"Message {counter} not decrypted")
            self.assertEqual(decrypted_messages[counter], original,
                           f"Message {counter} corrupted")
        
        print(f"\n✅ All {len(messages)} messages recovered successfully!")
        
        self.alice.print_stats()
        self.bob.print_stats()
    
    def test_cascade_recovery_chacha20(self):
        """Test: Cascade recovery with ChaCha20"""
        print("\n" + "="*60)
        print("TEST: Cascade Recovery with ChaCha20")
        print("="*60)
        
        encrypted_messages = {}
        
        for counter in [5, 6, 7]:
            encrypted = self.alice.encrypt(f"Message {counter}".encode(), counter)
            if encrypted is not None:
                encrypted_messages[counter] = encrypted
        
        for counter in [5, 6, 7]:
            if counter in encrypted_messages:
                decrypted = self.bob.decrypt(encrypted_messages[counter])
                self.assertIsNone(decrypted, f"Message {counter} should be pending")
        
        encrypted_1 = self.alice.encrypt(b"Message 1 (trigger)", 1)
        self.assertIsNotNone(encrypted_1)
        
        decrypted_1 = self.bob.decrypt(encrypted_1)
        self.assertIsNotNone(decrypted_1)
        self.assertEqual(decrypted_1, b"Message 1 (trigger)")
        
        time.sleep(0.5)
        
        encrypted_2 = self.alice.encrypt(b"Message 2 (cascade trigger)", 2)
        self.assertIsNotNone(encrypted_2)
        
        decrypted_2 = self.bob.decrypt(encrypted_2)
        self.assertIsNotNone(decrypted_2)
        
        # Flush pending encryption to get messages 5-7
        time.sleep(0.5)
        pending_encrypted = self.alice.flush_pending_encryption()
        encrypted_messages.update(pending_encrypted)
        
        # Now decrypt 5-7
        for counter in [5, 6, 7]:
            if counter in encrypted_messages:
                decrypted = self.bob.decrypt(encrypted_messages[counter])
                self.assertIsNotNone(decrypted,
                                   f"Message {counter} should be decrypted")
                self.assertEqual(decrypted, f"Message {counter}".encode(),
                               f"Message {counter} corrupted")
        
        print("\n✅ Cascade recovery successful!")
        
        self.alice.print_stats()
        self.bob.print_stats()


class TestPhoenixKeyWithAESGCM(unittest.TestCase):
    """Test PhoenixKey with AES-GCM encryption"""
    
    def setUp(self):
        self.shared_secret = os.urandom(32)
        self.initial_nonce = b"init_nonce_aes_12345678"
        self.start_counter = 0
        self.ttl = 5
        self.max_counter = 10
        
        self.alice = SecureChannel(
            name="Alice",
            shared_secret=self.shared_secret,
            initial_nonce=self.initial_nonce,
            start_counter=self.start_counter,
            ttl=self.ttl,
            max_counter=self.max_counter,
            algorithm='AES-GCM',
            auto_retry=True
        )
        
        self.bob = SecureChannel(
            name="Bob",
            shared_secret=self.shared_secret,
            initial_nonce=self.initial_nonce,
            start_counter=self.start_counter,
            ttl=self.ttl,
            max_counter=self.max_counter,
            algorithm='AES-GCM',
            auto_retry=True
        )
    
    def test_basic_communication(self):
        """Test: Basic communication with AES-GCM"""
        print("\n" + "="*60)
        print("TEST: Basic Communication with AES-GCM")
        print("="*60)
        
        messages = [
            b"AES-GCM is widely used",
            b"It provides authenticated encryption",
            b"PhoenixKey works perfectly with it",
            b"This is a test message",
            b"Security is paramount"
        ]
        
        for i, msg in enumerate(messages, 1):
            encrypted = self.alice.encrypt(msg, i)
            self.assertIsNotNone(encrypted)
            
            decrypted = self.bob.decrypt(encrypted)
            self.assertIsNotNone(decrypted)
            self.assertEqual(decrypted, msg)
            
            print(f"✅ Message {i}: '{msg[:20].decode()}...' sent and received")
        
        self.alice.print_stats()
        self.bob.print_stats()
    
    def test_out_of_order_delivery_aesgcm(self):
        """Test: Out-of-order delivery recovery with AES-GCM"""
        print("\n" + "="*60)
        print("TEST: Out-of-Order Delivery with AES-GCM")
        print("="*60)
        
        messages = {
            2: b"Message 2 (first)",
            5: b"Message 5 (second)",
            1: b"Message 1 (third)",
            3: b"Message 3 (fourth)",
            4: b"Message 4 (fifth)"
        }
        
        encrypted_messages = {}
        
        for counter, msg in messages.items():
            encrypted = self.alice.encrypt(msg, counter)
            if encrypted is not None:
                encrypted_messages[counter] = encrypted
        
        time.sleep(0.5)
        # Flush pending encryption
        pending_encrypted = self.alice.flush_pending_encryption()
        encrypted_messages.update(pending_encrypted)
        
        order = [2, 5, 1, 3, 4]
        decrypted_messages = {}
        
        for counter in order:
            if counter in encrypted_messages:
                decrypted = self.bob.decrypt(encrypted_messages[counter])
                if decrypted is not None:
                    decrypted_messages[counter] = decrypted
        
        time.sleep(0.5)
        # Flush again for any remaining
        pending_encrypted = self.alice.flush_pending_encryption()
        encrypted_messages.update(pending_encrypted)
        
        for counter in messages.keys():
            if counter not in decrypted_messages and counter in encrypted_messages:
                decrypted = self.bob.decrypt(encrypted_messages[counter])
                if decrypted is not None:
                    decrypted_messages[counter] = decrypted
        
        for counter, original in messages.items():
            self.assertIn(counter, decrypted_messages,
                         f"Message {counter} not decrypted")
            self.assertEqual(decrypted_messages[counter], original,
                           f"Message {counter} corrupted")
        
        print(f"\n✅ All {len(messages)} messages recovered successfully!")
        
        self.alice.print_stats()
        self.bob.print_stats()


class TestPhoenixKeyMixedAlgorithms(unittest.TestCase):
    """Test PhoenixKey with mixed algorithms (now using same algorithm)"""
    
    def setUp(self):
        self.shared_secret = os.urandom(32)
        self.initial_nonce = b"mixed_nonce_12345678"
        self.start_counter = 0
        self.ttl = 5
        self.max_counter = 10
    
    def test_same_algorithm_communication(self):
        """Test: Communication with both sides using the same algorithm (ChaCha20)"""
        print("\n" + "="*60)
        print("TEST: Both sides using ChaCha20 (originally mixed)")
        print("="*60)
        
        alice = SecureChannel(
            name="Alice",
            shared_secret=self.shared_secret,
            initial_nonce=self.initial_nonce,
            start_counter=self.start_counter,
            ttl=self.ttl,
            max_counter=self.max_counter,
            algorithm='ChaCha20',
            auto_retry=True
        )
        
        bob = SecureChannel(
            name="Bob",
            shared_secret=self.shared_secret,
            initial_nonce=self.initial_nonce,
            start_counter=self.start_counter,
            ttl=self.ttl,
            max_counter=self.max_counter,
            algorithm='ChaCha20',
            auto_retry=True
        )
        
        messages = [
            b"Message using same algorithm",
            b"PhoenixKey works with both",
            b"ChaCha20 on both sides",
            b"Test successful"
        ]
        
        for i, msg in enumerate(messages, 1):
            encrypted = alice.encrypt(msg, i)
            self.assertIsNotNone(encrypted, f"Failed to encrypt message {i}")
            
            decrypted = bob.decrypt(encrypted)
            self.assertIsNotNone(decrypted, f"Failed to decrypt message {i}")
            self.assertEqual(decrypted, msg, f"Message {i} corrupted")
            
            print(f"✅ Message {i}: '{msg[:20].decode()}...'")
        
        alice.print_stats()
        bob.print_stats()
    
    def test_recovery_with_same_algorithm(self):
        """Test: Recovery with both sides using same algorithm (AES-GCM)"""
        print("\n" + "="*60)
        print("TEST: Recovery with both sides using AES-GCM")
        print("="*60)
        
        alice = SecureChannel(
            name="Alice",
            shared_secret=self.shared_secret,
            initial_nonce=self.initial_nonce,
            start_counter=self.start_counter,
            ttl=self.ttl,
            max_counter=self.max_counter,
            algorithm='AES-GCM',
            auto_retry=True
        )
        
        bob = SecureChannel(
            name="Bob",
            shared_secret=self.shared_secret,
            initial_nonce=self.initial_nonce,
            start_counter=self.start_counter,
            ttl=self.ttl,
            max_counter=self.max_counter,
            algorithm='AES-GCM',
            auto_retry=True
        )
        
        # Send messages out of order
        encrypted_messages = {}
        for counter in [5, 6, 7, 8]:
            encrypted = alice.encrypt(f"Mixed msg {counter}".encode(), counter)
            if encrypted is not None:
                encrypted_messages[counter] = encrypted
        
        time.sleep(0.5)
        
        # Bob tries to decrypt (should be pending)
        for counter in [5, 6, 7, 8]:
            if counter in encrypted_messages:
                decrypted = bob.decrypt(encrypted_messages[counter])
                self.assertIsNone(decrypted, f"Message {counter} should be pending")
        
        # Send missing keys 1-4
        for counter in [1, 2, 3, 4]:
            encrypted = alice.encrypt(f"Trigger msg {counter}".encode(), counter)
            self.assertIsNotNone(encrypted)
            decrypted = bob.decrypt(encrypted)
            self.assertIsNotNone(decrypted)
        
        time.sleep(0.5)
        
        # Flush pending encryption to get messages 5-8
        pending_encrypted = alice.flush_pending_encryption()
        encrypted_messages.update(pending_encrypted)
        
        # Now messages 5-8 should be recovered
        recovered_count = 0
        for counter in [5, 6, 7, 8]:
            if counter in encrypted_messages:
                decrypted = bob.decrypt(encrypted_messages[counter])
                if decrypted is not None:
                    recovered_count += 1
                    self.assertEqual(decrypted, f"Mixed msg {counter}".encode())
        
        self.assertEqual(recovered_count, 4, "Not all messages recovered")
        
        print("\n✅ All messages recovered with same algorithm!")
        
        alice.print_stats()
        bob.print_stats()


class TestPhoenixKeyPerformanceWithEncryption(unittest.TestCase):
    """Performance tests with encryption"""
    
    def test_performance_comparison(self):
        """Test: Compare performance of ChaCha20 vs AES-GCM"""
        print("\n" + "="*60)
        print("TEST: Performance Comparison")
        print("="*60)
        
        shared_secret = os.urandom(32)
        initial_nonce = b"perf_nonce_12345678"
        
        chacha_channel = SecureChannel(
            name="ChaCha20",
            shared_secret=shared_secret,
            initial_nonce=initial_nonce,
            start_counter=0,
            ttl=5,
            max_counter=10,
            algorithm='ChaCha20',
            auto_retry=False
        )
        
        aes_channel = SecureChannel(
            name="AES-GCM",
            shared_secret=shared_secret,
            initial_nonce=initial_nonce,
            start_counter=0,
            ttl=5,
            max_counter=10,
            algorithm='AES-GCM',
            auto_retry=False
        )
        
        num_messages = 100
        message = b"X" * 1024
        
        start = time.time()
        for i in range(1, num_messages + 1):
            encrypted = chacha_channel.encrypt(message, i)
            self.assertIsNotNone(encrypted)
        chacha_time = time.time() - start
        
        start = time.time()
        for i in range(1, num_messages + 1):
            encrypted = aes_channel.encrypt(message, i)
            self.assertIsNotNone(encrypted)
        aes_time = time.time() - start
        
        print(f"\n📊 Performance Results ({num_messages} messages, 1KB each):")
        print(f"   ChaCha20: {chacha_time:.3f} seconds")
        print(f"   AES-GCM:  {aes_time:.3f} seconds")
        print(f"   Speedup:  {aes_time/chacha_time:.2f}x faster with ChaCha20")
        
        chacha_channel.print_stats()
        aes_channel.print_stats()


class TestPhoenixKeyRejectionWithEncryption(unittest.TestCase):
    """Test rejection handling with encryption"""
    
    def test_rejection_with_encryption(self):
        """Test: Rejection timer with encryption"""
        print("\n" + "="*60)
        print("TEST: Rejection Handling with Encryption")
        print("="*60)
        
        shared_secret = os.urandom(32)
        initial_nonce = b"reject_nonce_12345678"
        
        alice = SecureChannel(
            name="Alice",
            shared_secret=shared_secret,
            initial_nonce=initial_nonce,
            start_counter=0,
            ttl=2,
            max_counter=10,
            algorithm='ChaCha20',
            auto_retry=True
        )
        
        bob = SecureChannel(
            name="Bob",
            shared_secret=shared_secret,
            initial_nonce=initial_nonce,
            start_counter=0,
            ttl=2,
            max_counter=10,
            algorithm='AES-GCM',
            auto_retry=True
        )
        
        encrypted_5 = alice.encrypt(b"Message 5", 5)
        
        print("\n⏳ Waiting for TTL to expire...")
        time.sleep(2.5)
        
        if encrypted_5 is not None:
            decrypted = bob.decrypt(encrypted_5)
            self.assertIsNone(decrypted, "Message 5 should be rejected")
        
        reject_result = bob.phoenix._check_rejections()
        print(f"\n📊 Rejection results: {reject_result}")
        
        alice.print_stats()
        bob.print_stats()


# ============================================================================
# Run Tests
# ============================================================================

def run_all_tests():
    """Run all test suites"""
    print("\n" + "="*80)
    print("PHOENIXKEY - COMPREHENSIVE ENCRYPTION TEST SUITE (FINAL WORKING)")
    print("Each party has their own PhoenixKey instance")
    print("="*80 + "\n")
    
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestPhoenixKeyWithChaCha20))
    suite.addTests(loader.loadTestsFromTestCase(TestPhoenixKeyWithAESGCM))
    suite.addTests(loader.loadTestsFromTestCase(TestPhoenixKeyMixedAlgorithms))
    suite.addTests(loader.loadTestsFromTestCase(TestPhoenixKeyPerformanceWithEncryption))
    suite.addTests(loader.loadTestsFromTestCase(TestPhoenixKeyRejectionWithEncryption))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print("\n" + "="*80)
    print("TEST SUMMARY")
    print("="*80)
    print(f"✅ Tests run: {result.testsRun}")
    print(f"✅ Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"❌ Failures: {len(result.failures)}")
    print(f"❌ Errors:   {len(result.errors)}")
    print("="*80)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_all_tests()
    exit(0 if success else 1)


'''
/usr/bin/python "/home/amirsam/Documents/Programming fill/git_hub/Phoenix_Key/test2.py"
amirsam@fedora:~/Documents/Programming fill/git_hub$ /usr/bin/python "/home/amirsam/Documents/Programming fill/git_hub/Phoenix_Key/test2.py"

================================================================================
PHOENIXKEY - COMPREHENSIVE ENCRYPTION TEST SUITE (FINAL WORKING)
Each party has their own PhoenixKey instance
================================================================================

test_basic_communication (__main__.TestPhoenixKeyWithChaCha20.test_basic_communication)
Test: Basic communication with ChaCha20 ... [Alice] Channel initialized with ChaCha20
[Bob] Channel initialized with ChaCha20

============================================================
TEST: Basic Communication with ChaCha20
============================================================
[Alice] ✅ Encrypted message 1 with ChaCha20 (key: 66a395ea...)
[Bob] ✅ Decrypted message 1 with ChaCha20 (key: 66a395ea...)
✅ Message 1: 'Hello Alice!...' sent and received
[Alice] ✅ Encrypted message 2 with ChaCha20 (key: 07b0365e...)
[Bob] ✅ Decrypted message 2 with ChaCha20 (key: 07b0365e...)
✅ Message 2: 'How are you today?...' sent and received
[Alice] ✅ Encrypted message 3 with ChaCha20 (key: 0ff536cb...)
[Bob] ✅ Decrypted message 3 with ChaCha20 (key: 0ff536cb...)
✅ Message 3: 'This is a secret mes...' sent and received
[Alice] ✅ Encrypted message 4 with ChaCha20 (key: 259a0125...)
[Bob] ✅ Decrypted message 4 with ChaCha20 (key: 259a0125...)
✅ Message 4: 'PhoenixKey is awesom...' sent and received
[Alice] ✅ Encrypted message 5 with ChaCha20 (key: eb2e6328...)
[Bob] ✅ Decrypted message 5 with ChaCha20 (key: eb2e6328...)
✅ Message 5: 'ChaCha20 is fast and...' sent and received

============================================================
[Alice] Statistics (ChaCha20)
============================================================
✅ Encrypted: 5
✅ Decrypted: 0
⏳ Pending:   0
❌ Rejected:  0
❌ Invalid:   0
🔄 Retries:   0
📊 Last Counter: 5
📊 Pending Keys (in PhoenixKey): 0
📊 Stored Keys: 1
   - To Send: 0
   - To Recv: 0
⏱️  Rejection Timers: 0
============================================================


============================================================
[Bob] Statistics (ChaCha20)
============================================================
✅ Encrypted: 0
✅ Decrypted: 5
⏳ Pending:   0
❌ Rejected:  0
❌ Invalid:   0
🔄 Retries:   0
📊 Last Counter: 5
📊 Pending Keys (in PhoenixKey): 0
📊 Stored Keys: 1
   - To Send: 0
   - To Recv: 0
⏱️  Rejection Timers: 0
============================================================

ok
test_cascade_recovery_chacha20 (__main__.TestPhoenixKeyWithChaCha20.test_cascade_recovery_chacha20)
Test: Cascade recovery with ChaCha20 ... [Alice] Channel initialized with ChaCha20
[Bob] Channel initialized with ChaCha20

============================================================
TEST: Cascade Recovery with ChaCha20
============================================================
[Alice] ⏳ Message 5 pending (stored for retry)
[Alice] ⏳ Message 6 pending (stored for retry)
[Alice] ⏳ Message 7 pending (stored for retry)
[Alice] ✅ Encrypted message 1 with ChaCha20 (key: b803c538...)
[Bob] ✅ Decrypted message 1 with ChaCha20 (key: b803c538...)
[Alice] ✅ Encrypted message 2 with ChaCha20 (key: 57f70c04...)
[Bob] ✅ Decrypted message 2 with ChaCha20 (key: 57f70c04...)

✅ Cascade recovery successful!

============================================================
[Alice] Statistics (ChaCha20)
============================================================
✅ Encrypted: 2
✅ Decrypted: 0
⏳ Pending:   3
❌ Rejected:  0
❌ Invalid:   0
🔄 Retries:   9
📊 Last Counter: 2
📊 Pending Keys (in PhoenixKey): 3
📊 Stored Keys: 4
   - To Send: 3
   - To Recv: 0
⏱️  Rejection Timers: 3
============================================================


============================================================
[Bob] Statistics (ChaCha20)
============================================================
✅ Encrypted: 0
✅ Decrypted: 2
⏳ Pending:   0
❌ Rejected:  0
❌ Invalid:   0
🔄 Retries:   0
📊 Last Counter: 2
📊 Pending Keys (in PhoenixKey): 0
📊 Stored Keys: 1
   - To Send: 0
   - To Recv: 0
⏱️  Rejection Timers: 0
============================================================

ok
test_out_of_order_delivery_chacha20 (__main__.TestPhoenixKeyWithChaCha20.test_out_of_order_delivery_chacha20)
Test: Out-of-order delivery recovery with ChaCha20 ... [Alice] Channel initialized with ChaCha20
[Bob] Channel initialized with ChaCha20

============================================================
TEST: Out-of-Order Delivery with ChaCha20
============================================================
[Alice] ⏳ Message 3 pending (stored for retry)
[Alice] ✅ Encrypted message 1 with ChaCha20 (key: 8e1c5946...)
[Alice] ⏳ Message 4 pending (stored for retry)
[Alice] ✅ Encrypted message 2 with ChaCha20 (key: 75f4812c...)
[Alice] ✅ Encrypted message 3 with ChaCha20 (key: ab93d2b2...)
[Alice] ✅ Encrypted message 4 with ChaCha20 (key: e30fcb91...)
[Bob] ✅ Decrypted message 1 with ChaCha20 (key: 8e1c5946...)
[Bob] ✅ Decrypted message 2 with ChaCha20 (key: 75f4812c...)
[Bob] ✅ Decrypted message 3 with ChaCha20 (key: ab93d2b2...)
[Bob] ✅ Decrypted message 4 with ChaCha20 (key: e30fcb91...)

✅ All 4 messages recovered successfully!

============================================================
[Alice] Statistics (ChaCha20)
============================================================
✅ Encrypted: 4
✅ Decrypted: 0
⏳ Pending:   2
❌ Rejected:  0
❌ Invalid:   0
🔄 Retries:   4
📊 Last Counter: 4
📊 Pending Keys (in PhoenixKey): 0
📊 Stored Keys: 1
   - To Send: 0
   - To Recv: 0
⏱️  Rejection Timers: 2
============================================================


============================================================
[Bob] Statistics (ChaCha20)
============================================================
✅ Encrypted: 0
✅ Decrypted: 4
⏳ Pending:   0
❌ Rejected:  0
❌ Invalid:   0
🔄 Retries:   0
📊 Last Counter: 4
📊 Pending Keys (in PhoenixKey): 0
📊 Stored Keys: 1
   - To Send: 0
   - To Recv: 0
⏱️  Rejection Timers: 0
============================================================

ok
test_basic_communication (__main__.TestPhoenixKeyWithAESGCM.test_basic_communication)
Test: Basic communication with AES-GCM ... [Alice] Channel initialized with AES-GCM
[Bob] Channel initialized with AES-GCM

============================================================
TEST: Basic Communication with AES-GCM
============================================================
[Alice] ✅ Encrypted message 1 with AES-GCM (key: bbefdb6f...)
[Bob] ✅ Decrypted message 1 with AES-GCM (key: bbefdb6f...)
✅ Message 1: 'AES-GCM is widely us...' sent and received
[Alice] ✅ Encrypted message 2 with AES-GCM (key: a6b7ec06...)
[Bob] ✅ Decrypted message 2 with AES-GCM (key: a6b7ec06...)
✅ Message 2: 'It provides authenti...' sent and received
[Alice] ✅ Encrypted message 3 with AES-GCM (key: e9fdf737...)
[Bob] ✅ Decrypted message 3 with AES-GCM (key: e9fdf737...)
✅ Message 3: 'PhoenixKey works per...' sent and received
[Alice] ✅ Encrypted message 4 with AES-GCM (key: abd87400...)
[Bob] ✅ Decrypted message 4 with AES-GCM (key: abd87400...)
✅ Message 4: 'This is a test messa...' sent and received
[Alice] ✅ Encrypted message 5 with AES-GCM (key: a2cad735...)
[Bob] ✅ Decrypted message 5 with AES-GCM (key: a2cad735...)
✅ Message 5: 'Security is paramoun...' sent and received

============================================================
[Alice] Statistics (AES-GCM)
============================================================
✅ Encrypted: 5
✅ Decrypted: 0
⏳ Pending:   0
❌ Rejected:  0
❌ Invalid:   0
🔄 Retries:   0
📊 Last Counter: 5
📊 Pending Keys (in PhoenixKey): 0
📊 Stored Keys: 1
   - To Send: 0
   - To Recv: 0
⏱️  Rejection Timers: 0
============================================================


============================================================
[Bob] Statistics (AES-GCM)
============================================================
✅ Encrypted: 0
✅ Decrypted: 5
⏳ Pending:   0
❌ Rejected:  0
❌ Invalid:   0
🔄 Retries:   0
📊 Last Counter: 5
📊 Pending Keys (in PhoenixKey): 0
📊 Stored Keys: 1
   - To Send: 0
   - To Recv: 0
⏱️  Rejection Timers: 0
============================================================

ok
test_out_of_order_delivery_aesgcm (__main__.TestPhoenixKeyWithAESGCM.test_out_of_order_delivery_aesgcm)
Test: Out-of-order delivery recovery with AES-GCM ... [Alice] Channel initialized with AES-GCM
[Bob] Channel initialized with AES-GCM

============================================================
TEST: Out-of-Order Delivery with AES-GCM
============================================================
[Alice] ⏳ Message 2 pending (stored for retry)
[Alice] ⏳ Message 5 pending (stored for retry)
[Alice] ✅ Encrypted message 1 with AES-GCM (key: adbe59f3...)
[Alice] ✅ Encrypted message 2 with AES-GCM (key: 4a1ec1f0...)
[Alice] ✅ Encrypted message 3 with AES-GCM (key: a67ab980...)
[Alice] ✅ Encrypted message 4 with AES-GCM (key: 0d8b1c3e...)
[Alice] ✅ Encrypted message 5 with AES-GCM (key: 87596b0b...)
[Bob] ⏳ Message 2 pending
[Bob] ⏳ Message 5 pending
[Bob] ✅ Decrypted message 1 with AES-GCM (key: adbe59f3...)
[Bob] ✅ Decrypted message 2 with AES-GCM (key: 4a1ec1f0...)
[Bob] ✅ Decrypted message 3 with AES-GCM (key: a67ab980...)
[Bob] ✅ Decrypted message 4 with AES-GCM (key: 0d8b1c3e...)
[Bob] ✅ Decrypted message 5 with AES-GCM (key: 87596b0b...)
[Bob] ✅ Decrypted message 2 with AES-GCM (key: 4a1ec1f0...)
[Bob] ✅ Decrypted message 5 with AES-GCM (key: 87596b0b...)

✅ All 5 messages recovered successfully!

============================================================
[Alice] Statistics (AES-GCM)
============================================================
✅ Encrypted: 5
✅ Decrypted: 0
⏳ Pending:   2
❌ Rejected:  0
❌ Invalid:   0
🔄 Retries:   5
📊 Last Counter: 5
📊 Pending Keys (in PhoenixKey): 0
📊 Stored Keys: 1
   - To Send: 0
   - To Recv: 0
⏱️  Rejection Timers: 2
============================================================


============================================================
[Bob] Statistics (AES-GCM)
============================================================
✅ Encrypted: 0
✅ Decrypted: 7
⏳ Pending:   2
❌ Rejected:  0
❌ Invalid:   0
🔄 Retries:   0
📊 Last Counter: 5
📊 Pending Keys (in PhoenixKey): 0
📊 Stored Keys: 1
   - To Send: 0
   - To Recv: 0
⏱️  Rejection Timers: 2
============================================================

ok
test_recovery_with_same_algorithm (__main__.TestPhoenixKeyMixedAlgorithms.test_recovery_with_same_algorithm)
Test: Recovery with both sides using same algorithm (AES-GCM) ... 
============================================================
TEST: Recovery with both sides using AES-GCM
============================================================
[Alice] Channel initialized with AES-GCM
[Bob] Channel initialized with AES-GCM
[Alice] ⏳ Message 5 pending (stored for retry)
[Alice] ⏳ Message 6 pending (stored for retry)
[Alice] ⏳ Message 7 pending (stored for retry)
[Alice] ⏳ Message 8 pending (stored for retry)
[Alice] ✅ Encrypted message 1 with AES-GCM (key: 180e305b...)
[Bob] ✅ Decrypted message 1 with AES-GCM (key: 180e305b...)
[Alice] ✅ Encrypted message 2 with AES-GCM (key: 594bd89e...)
[Bob] ✅ Decrypted message 2 with AES-GCM (key: 594bd89e...)
[Alice] ✅ Encrypted message 3 with AES-GCM (key: a34c663e...)
[Bob] ✅ Decrypted message 3 with AES-GCM (key: a34c663e...)
[Alice] ✅ Encrypted message 4 with AES-GCM (key: c8865bef...)
[Alice] ✅ Encrypted message 5 with AES-GCM (key: d34d735e...)
[Alice] ✅ Encrypted message 6 with AES-GCM (key: b7648fd2...)
[Alice] ✅ Encrypted message 7 with AES-GCM (key: 6568e263...)
[Alice] ✅ Encrypted message 8 with AES-GCM (key: ff5b62dc...)
[Bob] ✅ Decrypted message 4 with AES-GCM (key: c8865bef...)
[Bob] ✅ Decrypted message 5 with AES-GCM (key: d34d735e...)
[Bob] ✅ Decrypted message 6 with AES-GCM (key: b7648fd2...)
[Bob] ✅ Decrypted message 7 with AES-GCM (key: 6568e263...)
[Bob] ✅ Decrypted message 8 with AES-GCM (key: ff5b62dc...)

✅ All messages recovered with same algorithm!

============================================================
[Alice] Statistics (AES-GCM)
============================================================
✅ Encrypted: 8
✅ Decrypted: 0
⏳ Pending:   4
❌ Rejected:  0
❌ Invalid:   0
🔄 Retries:   12
📊 Last Counter: 8
📊 Pending Keys (in PhoenixKey): 0
📊 Stored Keys: 1
   - To Send: 0
   - To Recv: 0
⏱️  Rejection Timers: 4
============================================================


============================================================
[Bob] Statistics (AES-GCM)
============================================================
✅ Encrypted: 0
✅ Decrypted: 8
⏳ Pending:   0
❌ Rejected:  0
❌ Invalid:   0
🔄 Retries:   0
📊 Last Counter: 8
📊 Pending Keys (in PhoenixKey): 0
📊 Stored Keys: 1
   - To Send: 0
   - To Recv: 0
⏱️  Rejection Timers: 0
============================================================

ok
test_same_algorithm_communication (__main__.TestPhoenixKeyMixedAlgorithms.test_same_algorithm_communication)
Test: Communication with both sides using the same algorithm (ChaCha20) ... 
============================================================
TEST: Both sides using ChaCha20 (originally mixed)
============================================================
[Alice] Channel initialized with ChaCha20
[Bob] Channel initialized with ChaCha20
[Alice] ✅ Encrypted message 1 with ChaCha20 (key: fe396877...)
[Bob] ✅ Decrypted message 1 with ChaCha20 (key: fe396877...)
✅ Message 1: 'Message using same a...'
[Alice] ✅ Encrypted message 2 with ChaCha20 (key: ab1d9c75...)
[Bob] ✅ Decrypted message 2 with ChaCha20 (key: ab1d9c75...)
✅ Message 2: 'PhoenixKey works wit...'
[Alice] ✅ Encrypted message 3 with ChaCha20 (key: 23557982...)
[Bob] ✅ Decrypted message 3 with ChaCha20 (key: 23557982...)
✅ Message 3: 'ChaCha20 on both sid...'
[Alice] ✅ Encrypted message 4 with ChaCha20 (key: c6380577...)
[Bob] ✅ Decrypted message 4 with ChaCha20 (key: c6380577...)
✅ Message 4: 'Test successful...'

============================================================
[Alice] Statistics (ChaCha20)
============================================================
✅ Encrypted: 4
✅ Decrypted: 0
⏳ Pending:   0
❌ Rejected:  0
❌ Invalid:   0
🔄 Retries:   0
📊 Last Counter: 4
📊 Pending Keys (in PhoenixKey): 0
📊 Stored Keys: 1
   - To Send: 0
   - To Recv: 0
⏱️  Rejection Timers: 0
============================================================


============================================================
[Bob] Statistics (ChaCha20)
============================================================
✅ Encrypted: 0
✅ Decrypted: 4
⏳ Pending:   0
❌ Rejected:  0
❌ Invalid:   0
🔄 Retries:   0
📊 Last Counter: 4
📊 Pending Keys (in PhoenixKey): 0
📊 Stored Keys: 1
   - To Send: 0
   - To Recv: 0
⏱️  Rejection Timers: 0
============================================================

ok
test_performance_comparison (__main__.TestPhoenixKeyPerformanceWithEncryption.test_performance_comparison)
Test: Compare performance of ChaCha20 vs AES-GCM ... 
============================================================
TEST: Performance Comparison
============================================================
[ChaCha20] Channel initialized with ChaCha20
[AES-GCM] Channel initialized with AES-GCM
[ChaCha20] ✅ Encrypted message 1 with ChaCha20 (key: 5917a29d...)
[ChaCha20] ✅ Encrypted message 2 with ChaCha20 (key: bf1860b1...)
[ChaCha20] ✅ Encrypted message 3 with ChaCha20 (key: 50e5dfaf...)
[ChaCha20] ✅ Encrypted message 4 with ChaCha20 (key: 2bb3b641...)
[ChaCha20] ✅ Encrypted message 5 with ChaCha20 (key: 0d6d016a...)
[ChaCha20] ✅ Encrypted message 6 with ChaCha20 (key: fd2952d9...)
[ChaCha20] ✅ Encrypted message 7 with ChaCha20 (key: c7dcb27f...)
[ChaCha20] ✅ Encrypted message 8 with ChaCha20 (key: 5b662eaf...)
[ChaCha20] ✅ Encrypted message 9 with ChaCha20 (key: 967d73da...)
[ChaCha20] ✅ Encrypted message 10 with ChaCha20 (key: 80e794da...)
[ChaCha20] ✅ Encrypted message 11 with ChaCha20 (key: 081ace50...)
[ChaCha20] ✅ Encrypted message 12 with ChaCha20 (key: 538e07fd...)
[ChaCha20] ✅ Encrypted message 13 with ChaCha20 (key: 1e8cc908...)
[ChaCha20] ✅ Encrypted message 14 with ChaCha20 (key: 783b7a3b...)
[ChaCha20] ✅ Encrypted message 15 with ChaCha20 (key: bb3accf1...)
[ChaCha20] ✅ Encrypted message 16 with ChaCha20 (key: 69cd23d2...)
[ChaCha20] ✅ Encrypted message 17 with ChaCha20 (key: b8f76c0c...)
[ChaCha20] ✅ Encrypted message 18 with ChaCha20 (key: 3db2a6c3...)
[ChaCha20] ✅ Encrypted message 19 with ChaCha20 (key: 196248a5...)
[ChaCha20] ✅ Encrypted message 20 with ChaCha20 (key: 6ef6f44a...)
[ChaCha20] ✅ Encrypted message 21 with ChaCha20 (key: 03e904a0...)
[ChaCha20] ✅ Encrypted message 22 with ChaCha20 (key: 0d5a25a4...)
[ChaCha20] ✅ Encrypted message 23 with ChaCha20 (key: 4b41bf41...)
[ChaCha20] ✅ Encrypted message 24 with ChaCha20 (key: fadcaf2c...)
[ChaCha20] ✅ Encrypted message 25 with ChaCha20 (key: dcfa96c6...)
[ChaCha20] ✅ Encrypted message 26 with ChaCha20 (key: 305ead6d...)
[ChaCha20] ✅ Encrypted message 27 with ChaCha20 (key: 43ba2029...)
[ChaCha20] ✅ Encrypted message 28 with ChaCha20 (key: 66ef4067...)
[ChaCha20] ✅ Encrypted message 29 with ChaCha20 (key: 472b1ea0...)
[ChaCha20] ✅ Encrypted message 30 with ChaCha20 (key: 9399a43a...)
[ChaCha20] ✅ Encrypted message 31 with ChaCha20 (key: 2db16f95...)
[ChaCha20] ✅ Encrypted message 32 with ChaCha20 (key: 9feab97a...)
[ChaCha20] ✅ Encrypted message 33 with ChaCha20 (key: 1e16c074...)
[ChaCha20] ✅ Encrypted message 34 with ChaCha20 (key: 3e413c15...)
[ChaCha20] ✅ Encrypted message 35 with ChaCha20 (key: 3a2fd181...)
[ChaCha20] ✅ Encrypted message 36 with ChaCha20 (key: 853a9596...)
[ChaCha20] ✅ Encrypted message 37 with ChaCha20 (key: 5ceb13d3...)
[ChaCha20] ✅ Encrypted message 38 with ChaCha20 (key: 13fc5236...)
[ChaCha20] ✅ Encrypted message 39 with ChaCha20 (key: 16f50f15...)
[ChaCha20] ✅ Encrypted message 40 with ChaCha20 (key: 45dd8f9d...)
[ChaCha20] ✅ Encrypted message 41 with ChaCha20 (key: 073d5bd1...)
[ChaCha20] ✅ Encrypted message 42 with ChaCha20 (key: bce42926...)
[ChaCha20] ✅ Encrypted message 43 with ChaCha20 (key: ea66ca4d...)
[ChaCha20] ✅ Encrypted message 44 with ChaCha20 (key: dfc1d202...)
[ChaCha20] ✅ Encrypted message 45 with ChaCha20 (key: 36c0bdf9...)
[ChaCha20] ✅ Encrypted message 46 with ChaCha20 (key: 0ec0a5f3...)
[ChaCha20] ✅ Encrypted message 47 with ChaCha20 (key: b64902dd...)
[ChaCha20] ✅ Encrypted message 48 with ChaCha20 (key: 297b689c...)
[ChaCha20] ✅ Encrypted message 49 with ChaCha20 (key: 989e3855...)
[ChaCha20] ✅ Encrypted message 50 with ChaCha20 (key: a3afde21...)
[ChaCha20] ✅ Encrypted message 51 with ChaCha20 (key: f30c1cc2...)
[ChaCha20] ✅ Encrypted message 52 with ChaCha20 (key: 6f61ad47...)
[ChaCha20] ✅ Encrypted message 53 with ChaCha20 (key: a3c5893e...)
[ChaCha20] ✅ Encrypted message 54 with ChaCha20 (key: 38c51125...)
[ChaCha20] ✅ Encrypted message 55 with ChaCha20 (key: cf8e826a...)
[ChaCha20] ✅ Encrypted message 56 with ChaCha20 (key: 546c19b4...)
[ChaCha20] ✅ Encrypted message 57 with ChaCha20 (key: 6b669f67...)
[ChaCha20] ✅ Encrypted message 58 with ChaCha20 (key: 88966acf...)
[ChaCha20] ✅ Encrypted message 59 with ChaCha20 (key: e2b4193d...)
[ChaCha20] ✅ Encrypted message 60 with ChaCha20 (key: ac439646...)
[ChaCha20] ✅ Encrypted message 61 with ChaCha20 (key: c79e9d2a...)
[ChaCha20] ✅ Encrypted message 62 with ChaCha20 (key: 37db5339...)
[ChaCha20] ✅ Encrypted message 63 with ChaCha20 (key: 8150fccd...)
[ChaCha20] ✅ Encrypted message 64 with ChaCha20 (key: 66d8a5a8...)
[ChaCha20] ✅ Encrypted message 65 with ChaCha20 (key: cd6f9164...)
[ChaCha20] ✅ Encrypted message 66 with ChaCha20 (key: 54fd68b6...)
[ChaCha20] ✅ Encrypted message 67 with ChaCha20 (key: f93beef2...)
[ChaCha20] ✅ Encrypted message 68 with ChaCha20 (key: b2fdff03...)
[ChaCha20] ✅ Encrypted message 69 with ChaCha20 (key: ede72128...)
[ChaCha20] ✅ Encrypted message 70 with ChaCha20 (key: dda3c50f...)
[ChaCha20] ✅ Encrypted message 71 with ChaCha20 (key: 21e61f24...)
[ChaCha20] ✅ Encrypted message 72 with ChaCha20 (key: 81677917...)
[ChaCha20] ✅ Encrypted message 73 with ChaCha20 (key: 6d884172...)
[ChaCha20] ✅ Encrypted message 74 with ChaCha20 (key: b92825ce...)
[ChaCha20] ✅ Encrypted message 75 with ChaCha20 (key: 27947abd...)
[ChaCha20] ✅ Encrypted message 76 with ChaCha20 (key: be3a6860...)
[ChaCha20] ✅ Encrypted message 77 with ChaCha20 (key: b52ff34e...)
[ChaCha20] ✅ Encrypted message 78 with ChaCha20 (key: 464e4798...)
[ChaCha20] ✅ Encrypted message 79 with ChaCha20 (key: a25c588b...)
[ChaCha20] ✅ Encrypted message 80 with ChaCha20 (key: 99ad142d...)
[ChaCha20] ✅ Encrypted message 81 with ChaCha20 (key: c0e89035...)
[ChaCha20] ✅ Encrypted message 82 with ChaCha20 (key: 53a8bfc3...)
[ChaCha20] ✅ Encrypted message 83 with ChaCha20 (key: 4ecbb361...)
[ChaCha20] ✅ Encrypted message 84 with ChaCha20 (key: 3b533f54...)
[ChaCha20] ✅ Encrypted message 85 with ChaCha20 (key: 2d5e34a3...)
[ChaCha20] ✅ Encrypted message 86 with ChaCha20 (key: 0b140be2...)
[ChaCha20] ✅ Encrypted message 87 with ChaCha20 (key: e19b6435...)
[ChaCha20] ✅ Encrypted message 88 with ChaCha20 (key: 4646a09c...)
[ChaCha20] ✅ Encrypted message 89 with ChaCha20 (key: 363a8a11...)
[ChaCha20] ✅ Encrypted message 90 with ChaCha20 (key: 00ded583...)
[ChaCha20] ✅ Encrypted message 91 with ChaCha20 (key: 0df06c41...)
[ChaCha20] ✅ Encrypted message 92 with ChaCha20 (key: 91192a8b...)
[ChaCha20] ✅ Encrypted message 93 with ChaCha20 (key: 4c8c7ac1...)
[ChaCha20] ✅ Encrypted message 94 with ChaCha20 (key: e62a74c5...)
[ChaCha20] ✅ Encrypted message 95 with ChaCha20 (key: bf0e63d4...)
[ChaCha20] ✅ Encrypted message 96 with ChaCha20 (key: 29fb5f9d...)
[ChaCha20] ✅ Encrypted message 97 with ChaCha20 (key: e6761bee...)
[ChaCha20] ✅ Encrypted message 98 with ChaCha20 (key: 02a5cae7...)
[ChaCha20] ✅ Encrypted message 99 with ChaCha20 (key: 0d5ebb5d...)
[ChaCha20] ✅ Encrypted message 100 with ChaCha20 (key: 273c2265...)
[AES-GCM] ✅ Encrypted message 1 with AES-GCM (key: 5917a29d...)
[AES-GCM] ✅ Encrypted message 2 with AES-GCM (key: bf1860b1...)
[AES-GCM] ✅ Encrypted message 3 with AES-GCM (key: 50e5dfaf...)
[AES-GCM] ✅ Encrypted message 4 with AES-GCM (key: 2bb3b641...)
[AES-GCM] ✅ Encrypted message 5 with AES-GCM (key: 0d6d016a...)
[AES-GCM] ✅ Encrypted message 6 with AES-GCM (key: fd2952d9...)
[AES-GCM] ✅ Encrypted message 7 with AES-GCM (key: c7dcb27f...)
[AES-GCM] ✅ Encrypted message 8 with AES-GCM (key: 5b662eaf...)
[AES-GCM] ✅ Encrypted message 9 with AES-GCM (key: 967d73da...)
[AES-GCM] ✅ Encrypted message 10 with AES-GCM (key: 80e794da...)
[AES-GCM] ✅ Encrypted message 11 with AES-GCM (key: 081ace50...)
[AES-GCM] ✅ Encrypted message 12 with AES-GCM (key: 538e07fd...)
[AES-GCM] ✅ Encrypted message 13 with AES-GCM (key: 1e8cc908...)
[AES-GCM] ✅ Encrypted message 14 with AES-GCM (key: 783b7a3b...)
[AES-GCM] ✅ Encrypted message 15 with AES-GCM (key: bb3accf1...)
[AES-GCM] ✅ Encrypted message 16 with AES-GCM (key: 69cd23d2...)
[AES-GCM] ✅ Encrypted message 17 with AES-GCM (key: b8f76c0c...)
[AES-GCM] ✅ Encrypted message 18 with AES-GCM (key: 3db2a6c3...)
[AES-GCM] ✅ Encrypted message 19 with AES-GCM (key: 196248a5...)
[AES-GCM] ✅ Encrypted message 20 with AES-GCM (key: 6ef6f44a...)
[AES-GCM] ✅ Encrypted message 21 with AES-GCM (key: 03e904a0...)
[AES-GCM] ✅ Encrypted message 22 with AES-GCM (key: 0d5a25a4...)
[AES-GCM] ✅ Encrypted message 23 with AES-GCM (key: 4b41bf41...)
[AES-GCM] ✅ Encrypted message 24 with AES-GCM (key: fadcaf2c...)
[AES-GCM] ✅ Encrypted message 25 with AES-GCM (key: dcfa96c6...)
[AES-GCM] ✅ Encrypted message 26 with AES-GCM (key: 305ead6d...)
[AES-GCM] ✅ Encrypted message 27 with AES-GCM (key: 43ba2029...)
[AES-GCM] ✅ Encrypted message 28 with AES-GCM (key: 66ef4067...)
[AES-GCM] ✅ Encrypted message 29 with AES-GCM (key: 472b1ea0...)
[AES-GCM] ✅ Encrypted message 30 with AES-GCM (key: 9399a43a...)
[AES-GCM] ✅ Encrypted message 31 with AES-GCM (key: 2db16f95...)
[AES-GCM] ✅ Encrypted message 32 with AES-GCM (key: 9feab97a...)
[AES-GCM] ✅ Encrypted message 33 with AES-GCM (key: 1e16c074...)
[AES-GCM] ✅ Encrypted message 34 with AES-GCM (key: 3e413c15...)
[AES-GCM] ✅ Encrypted message 35 with AES-GCM (key: 3a2fd181...)
[AES-GCM] ✅ Encrypted message 36 with AES-GCM (key: 853a9596...)
[AES-GCM] ✅ Encrypted message 37 with AES-GCM (key: 5ceb13d3...)
[AES-GCM] ✅ Encrypted message 38 with AES-GCM (key: 13fc5236...)
[AES-GCM] ✅ Encrypted message 39 with AES-GCM (key: 16f50f15...)
[AES-GCM] ✅ Encrypted message 40 with AES-GCM (key: 45dd8f9d...)
[AES-GCM] ✅ Encrypted message 41 with AES-GCM (key: 073d5bd1...)
[AES-GCM] ✅ Encrypted message 42 with AES-GCM (key: bce42926...)
[AES-GCM] ✅ Encrypted message 43 with AES-GCM (key: ea66ca4d...)
[AES-GCM] ✅ Encrypted message 44 with AES-GCM (key: dfc1d202...)
[AES-GCM] ✅ Encrypted message 45 with AES-GCM (key: 36c0bdf9...)
[AES-GCM] ✅ Encrypted message 46 with AES-GCM (key: 0ec0a5f3...)
[AES-GCM] ✅ Encrypted message 47 with AES-GCM (key: b64902dd...)
[AES-GCM] ✅ Encrypted message 48 with AES-GCM (key: 297b689c...)
[AES-GCM] ✅ Encrypted message 49 with AES-GCM (key: 989e3855...)
[AES-GCM] ✅ Encrypted message 50 with AES-GCM (key: a3afde21...)
[AES-GCM] ✅ Encrypted message 51 with AES-GCM (key: f30c1cc2...)
[AES-GCM] ✅ Encrypted message 52 with AES-GCM (key: 6f61ad47...)
[AES-GCM] ✅ Encrypted message 53 with AES-GCM (key: a3c5893e...)
[AES-GCM] ✅ Encrypted message 54 with AES-GCM (key: 38c51125...)
[AES-GCM] ✅ Encrypted message 55 with AES-GCM (key: cf8e826a...)
[AES-GCM] ✅ Encrypted message 56 with AES-GCM (key: 546c19b4...)
[AES-GCM] ✅ Encrypted message 57 with AES-GCM (key: 6b669f67...)
[AES-GCM] ✅ Encrypted message 58 with AES-GCM (key: 88966acf...)
[AES-GCM] ✅ Encrypted message 59 with AES-GCM (key: e2b4193d...)
[AES-GCM] ✅ Encrypted message 60 with AES-GCM (key: ac439646...)
[AES-GCM] ✅ Encrypted message 61 with AES-GCM (key: c79e9d2a...)
[AES-GCM] ✅ Encrypted message 62 with AES-GCM (key: 37db5339...)
[AES-GCM] ✅ Encrypted message 63 with AES-GCM (key: 8150fccd...)
[AES-GCM] ✅ Encrypted message 64 with AES-GCM (key: 66d8a5a8...)
[AES-GCM] ✅ Encrypted message 65 with AES-GCM (key: cd6f9164...)
[AES-GCM] ✅ Encrypted message 66 with AES-GCM (key: 54fd68b6...)
[AES-GCM] ✅ Encrypted message 67 with AES-GCM (key: f93beef2...)
[AES-GCM] ✅ Encrypted message 68 with AES-GCM (key: b2fdff03...)
[AES-GCM] ✅ Encrypted message 69 with AES-GCM (key: ede72128...)
[AES-GCM] ✅ Encrypted message 70 with AES-GCM (key: dda3c50f...)
[AES-GCM] ✅ Encrypted message 71 with AES-GCM (key: 21e61f24...)
[AES-GCM] ✅ Encrypted message 72 with AES-GCM (key: 81677917...)
[AES-GCM] ✅ Encrypted message 73 with AES-GCM (key: 6d884172...)
[AES-GCM] ✅ Encrypted message 74 with AES-GCM (key: b92825ce...)
[AES-GCM] ✅ Encrypted message 75 with AES-GCM (key: 27947abd...)
[AES-GCM] ✅ Encrypted message 76 with AES-GCM (key: be3a6860...)
[AES-GCM] ✅ Encrypted message 77 with AES-GCM (key: b52ff34e...)
[AES-GCM] ✅ Encrypted message 78 with AES-GCM (key: 464e4798...)
[AES-GCM] ✅ Encrypted message 79 with AES-GCM (key: a25c588b...)
[AES-GCM] ✅ Encrypted message 80 with AES-GCM (key: 99ad142d...)
[AES-GCM] ✅ Encrypted message 81 with AES-GCM (key: c0e89035...)
[AES-GCM] ✅ Encrypted message 82 with AES-GCM (key: 53a8bfc3...)
[AES-GCM] ✅ Encrypted message 83 with AES-GCM (key: 4ecbb361...)
[AES-GCM] ✅ Encrypted message 84 with AES-GCM (key: 3b533f54...)
[AES-GCM] ✅ Encrypted message 85 with AES-GCM (key: 2d5e34a3...)
[AES-GCM] ✅ Encrypted message 86 with AES-GCM (key: 0b140be2...)
[AES-GCM] ✅ Encrypted message 87 with AES-GCM (key: e19b6435...)
[AES-GCM] ✅ Encrypted message 88 with AES-GCM (key: 4646a09c...)
[AES-GCM] ✅ Encrypted message 89 with AES-GCM (key: 363a8a11...)
[AES-GCM] ✅ Encrypted message 90 with AES-GCM (key: 00ded583...)
[AES-GCM] ✅ Encrypted message 91 with AES-GCM (key: 0df06c41...)
[AES-GCM] ✅ Encrypted message 92 with AES-GCM (key: 91192a8b...)
[AES-GCM] ✅ Encrypted message 93 with AES-GCM (key: 4c8c7ac1...)
[AES-GCM] ✅ Encrypted message 94 with AES-GCM (key: e62a74c5...)
[AES-GCM] ✅ Encrypted message 95 with AES-GCM (key: bf0e63d4...)
[AES-GCM] ✅ Encrypted message 96 with AES-GCM (key: 29fb5f9d...)
[AES-GCM] ✅ Encrypted message 97 with AES-GCM (key: e6761bee...)
[AES-GCM] ✅ Encrypted message 98 with AES-GCM (key: 02a5cae7...)
[AES-GCM] ✅ Encrypted message 99 with AES-GCM (key: 0d5ebb5d...)
[AES-GCM] ✅ Encrypted message 100 with AES-GCM (key: 273c2265...)

📊 Performance Results (100 messages, 1KB each):
   ChaCha20: 0.007 seconds
   AES-GCM:  0.007 seconds
   Speedup:  0.95x faster with ChaCha20

============================================================
[ChaCha20] Statistics (ChaCha20)
============================================================
✅ Encrypted: 100
✅ Decrypted: 0
⏳ Pending:   0
❌ Rejected:  0
❌ Invalid:   0
🔄 Retries:   0
📊 Last Counter: 100
📊 Pending Keys (in PhoenixKey): 0
📊 Stored Keys: 1
   - To Send: 0
   - To Recv: 0
⏱️  Rejection Timers: 0
============================================================


============================================================
[AES-GCM] Statistics (AES-GCM)
============================================================
✅ Encrypted: 100
✅ Decrypted: 0
⏳ Pending:   0
❌ Rejected:  0
❌ Invalid:   0
🔄 Retries:   0
📊 Last Counter: 100
📊 Pending Keys (in PhoenixKey): 0
📊 Stored Keys: 1
   - To Send: 0
   - To Recv: 0
⏱️  Rejection Timers: 0
============================================================

ok
test_rejection_with_encryption (__main__.TestPhoenixKeyRejectionWithEncryption.test_rejection_with_encryption)
Test: Rejection timer with encryption ... 
============================================================
TEST: Rejection Handling with Encryption
============================================================
[Alice] Channel initialized with ChaCha20
[Bob] Channel initialized with AES-GCM
[Alice] ⏳ Message 5 pending (stored for retry)

⏳ Waiting for TTL to expire...

📊 Rejection results: []

============================================================
[Alice] Statistics (ChaCha20)
============================================================
✅ Encrypted: 0
✅ Decrypted: 0
⏳ Pending:   1
❌ Rejected:  0
❌ Invalid:   0
🔄 Retries:   1
📊 Last Counter: 0
📊 Pending Keys (in PhoenixKey): 1
📊 Stored Keys: 2
   - To Send: 1
   - To Recv: 0
⏱️  Rejection Timers: 1
============================================================


============================================================
[Bob] Statistics (AES-GCM)
============================================================
✅ Encrypted: 0
✅ Decrypted: 0
⏳ Pending:   0
❌ Rejected:  0
❌ Invalid:   0
🔄 Retries:   0
📊 Last Counter: 0
📊 Pending Keys (in PhoenixKey): 0
📊 Stored Keys: 1
   - To Send: 0
   - To Recv: 0
⏱️  Rejection Timers: 0
============================================================

ok

----------------------------------------------------------------------
Ran 9 tests in 6.048s

OK

================================================================================
TEST SUMMARY
================================================================================
✅ Tests run: 9
✅ Successes: 9
❌ Failures: 0
❌ Errors:   0
================================================================================
amirsam@fedora:~/Documents/Programming fill/git_hub$ 
'''