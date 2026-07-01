"""
Unit tests for PhoenixKey - A Secure Key Chain Management Protocol with Recovery Capability

These tests cover:
- Initialization and basic functionality
- Sequential key generation
- Out-of-order recovery (pending/cascade)
- Rejection timer handling
- Duplicate and range validation
- Edge cases and error conditions
- Integration scenarios
"""

import unittest
import time
import threading
from phoenix_key import PhoenixKey, Status


class TestPhoenixKeyInitialization(unittest.TestCase):
    """Test suite for PhoenixKey initialization and basic setup"""
    
    def setUp(self):
        """Common setup for all initialization tests"""
        self.pk = PhoenixKey(
            key=b"test_key_12345678901234567890",
            nonce=b"test_nonce_12345678",
            counter=0,
            ttl=5,
            max_counter=10
        )
    
    def test_initialization_success(self):
        """Test: PhoenixKey initializes correctly with valid parameters"""
        self.assertEqual(self.pk.ttl, 5)
        self.assertEqual(self.pk.max_counter, 10)
        self.assertEqual(self.pk.last_counter, 0)
        self.assertIn(0, self.pk.key_dict)
        self.assertTrue(self.pk.key_dict[0][2])
        self.assertEqual(len(self.pk.key_dict[0][0]), 32)
        self.assertEqual(self.pk.key_dict[0][1], b"test_nonce_12345678")
    
    def test_initial_key_derivation(self):
        """Test: Initial key is derived correctly using HKDF with BLAKE2s"""
        key = self.pk.key_dict[0][0]
        self.assertIsNotNone(key)
        self.assertEqual(len(key), 32)
        self.assertIsInstance(key, bytes)
    
    def test_initial_key_uniqueness(self):
        """Test: Different initial keys produce different results"""
        pk2 = PhoenixKey(
            key=b"different_key_12345678901234567890",
            nonce=b"test_nonce_12345678",
            counter=0,
            ttl=5,
            max_counter=10
        )
        self.assertNotEqual(self.pk.key_dict[0][0], pk2.key_dict[0][0])
    
    def test_different_start_counter(self):
        """Test: PhoenixKey works with non-zero starting counter"""
        pk = PhoenixKey(
            key=b"test_key_12345678901234567890",
            nonce=b"test_nonce_12345678",
            counter=100,
            ttl=5,
            max_counter=10
        )
        self.assertEqual(pk.last_counter, 100)
        self.assertIn(100, pk.key_dict)
        
        result = pk.check_key(b"nonce_101", 101)
        self.assertEqual(result[0][0], Status.SUCCESS)
        self.assertEqual(pk.last_counter, 101)
    
    def test_empty_nonce(self):
        """Test: PhoenixKey works with empty nonce"""
        pk = PhoenixKey(
            key=b"test_key_12345678901234567890",
            nonce=b"",
            counter=0,
            ttl=5,
            max_counter=10
        )
        self.assertEqual(pk.key_dict[0][1], b"")
        
        result = pk.check_key(b"", 1)
        self.assertEqual(result[0][0], Status.SUCCESS)
    
    def test_zero_ttl(self):
        """Test: PhoenixKey works with TTL = 0"""
        pk = PhoenixKey(
            key=b"test_key_12345678901234567890",
            nonce=b"test_nonce_12345678",
            counter=0,
            ttl=0,
            max_counter=10
        )
        self.assertEqual(pk.ttl, 0)
        
        result = pk.check_key(b"nonce_3", 3)
        self.assertEqual(result[0], Status.PENDING)
        self.assertIn(2, pk.key_dict_reject)
        self.assertAlmostEqual(pk.key_dict_reject[2], time.time(), delta=0.1)


class TestPhoenixKeySequential(unittest.TestCase):
    """Test suite for sequential key generation"""
    
    def setUp(self):
        """Common setup for sequential tests"""
        self.pk = PhoenixKey(
            key=b"test_key_12345678901234567890",
            nonce=b"test_nonce_12345678",
            counter=0,
            ttl=5,
            max_counter=10
        )
    
    def test_sequential_keys_1_to_5(self):
        """Test: Generate keys 1 through 5 in sequence"""
        for i in range(1, 6):
            result = self.pk.check_key(f"nonce_{i}".encode(), i)
            self.assertEqual(result[0][0], Status.SUCCESS, f"Failed at counter {i}")
            self.assertEqual(len(result[0][1]), 32)
            self.assertEqual(self.pk.last_counter, i)
        
        # Only the last key should remain in memory
        self.assertEqual(len(self.pk.key_dict), 1)
        self.assertIn(5, self.pk.key_dict)
        self.assertNotIn(4, self.pk.key_dict)
    
    def test_sequential_keys_with_different_nonces(self):
        """Test: Sequential keys with different nonces produce different keys"""
        keys = []
        for i in range(1, 4):
            result = self.pk.check_key(f"nonce_{i}".encode(), i)
            keys.append(result[0][1])
        
        self.assertEqual(len(set(keys)), len(keys))
        self.assertNotEqual(keys[0], keys[1])
        self.assertNotEqual(keys[1], keys[2])
    
    def test_sequential_keys_same_nonce_different_counter(self):
        """Test: Same nonce with different counters produces different keys"""
        key1 = self.pk._create_key(b"base_key", b"same_nonce", 1)
        key2 = self.pk._create_key(b"base_key", b"same_nonce", 2)
        self.assertNotEqual(key1, key2)
    
    def test_sequential_keys_large_counter(self):
        """Test: Large counter values work correctly"""
        self.pk.check_key(b"nonce_1", 1)
        for i in range(2, 1001):
            result = self.pk.check_key(f"nonce_{i}".encode(), i)
            self.assertEqual(result[0][0], Status.SUCCESS)
        
        self.assertEqual(self.pk.last_counter, 1000)
        self.assertEqual(len(self.pk.key_dict), 1)


class TestPhoenixKeyOutOfOrder(unittest.TestCase):
    """Test suite for out-of-order recovery and cascade effects"""
    
    def setUp(self):
        """Common setup for out-of-order tests"""
        self.pk = PhoenixKey(
            key=b"test_key_12345678901234567890",
            nonce=b"test_nonce_12345678",
            counter=0,
            ttl=5,
            max_counter=10
        )
    
    def test_out_of_order_pending(self):
        """Test: Out-of-order key goes into pending state"""
        result = self.pk.check_key(b"nonce_3", 3)
        
        self.assertEqual(result[0], Status.PENDING)
        self.assertEqual(result[1], 3)
        self.assertIn(3, self.pk.key_dict)
        self.assertIsNone(self.pk.key_dict[3][0])
        self.assertFalse(self.pk.key_dict[3][2])
        self.assertIn(2, self.pk.key_dict_reject)
        self.assertEqual(self.pk.last_counter, 0)
    
    def test_out_of_order_multiple_pending(self):
        """Test: Multiple out-of-order keys are stored as pending"""
        for i in range(3, 6):
            result = self.pk.check_key(f"nonce_{i}".encode(), i)
            self.assertEqual(result[0], Status.PENDING)
            self.assertEqual(result[1], i)
        
        self.assertIn(3, self.pk.key_dict)
        self.assertIn(4, self.pk.key_dict)
        self.assertIn(5, self.pk.key_dict)
        self.assertIsNone(self.pk.key_dict[3][0])
        self.assertIsNone(self.pk.key_dict[4][0])
        self.assertIsNone(self.pk.key_dict[5][0])
        
        self.assertIn(2, self.pk.key_dict_reject)
        self.assertIn(3, self.pk.key_dict_reject)
        self.assertIn(4, self.pk.key_dict_reject)
    
    def test_cascade_recovery_with_key1(self):
        """Test: When key 1 arrives, it triggers cascade recovery for keys 2 and 3"""
        self.pk.check_key(b"nonce_2", 2)
        self.pk.check_key(b"nonce_3", 3)
        
        result = self.pk.check_key(b"nonce_1", 1)
        
        self.assertEqual(len(result), 3)
        for i in range(3):
            self.assertEqual(result[i][0], Status.SUCCESS)
            self.assertEqual(len(result[i][1]), 32)
        
        self.assertEqual(self.pk.last_counter, 3)
        self.assertEqual(len(self.pk.key_dict), 1)
        self.assertIn(3, self.pk.key_dict)
    
    def test_cascade_recovery_with_key2_and_key4(self):
        """Test: When key 2 arrives, it triggers recovery for keys 2, 3, 4"""
        # Send keys 3 and 4 (skip 1 and 2)
        self.pk.check_key(b"nonce_3", 3)
        self.pk.check_key(b"nonce_4", 4)
        
        # Send key 1 (last_counter = 1)
        self.pk.check_key(b"nonce_1", 1)
        
        # Send key 2 - should trigger cascade: 2, 3, 4
        result = self.pk.check_key(b"nonce_2", 2)
        
        self.assertEqual(len(result), 3)  # Keys 2, 3, 4
        for i in range(3):
            self.assertEqual(result[i][0], Status.SUCCESS)
            self.assertEqual(len(result[i][1]), 32)
        
        self.assertEqual(self.pk.last_counter, 4)
        self.assertEqual(len(self.pk.key_dict), 1)
        self.assertIn(4, self.pk.key_dict)
    
    def test_cascade_recovery_complex_scenario(self):
        """Test: Complex out-of-order scenario with multiple gaps"""
        # Send keys 5, 6, 7, 8 (skip 1-4)
        for i in range(5, 9):
            self.pk.check_key(f"nonce_{i}".encode(), i)
        
        # Send key 1 (last_counter = 1)
        self.pk.check_key(b"nonce_1", 1)
        
        # Send keys 2, 3, 4 in sequence
        self.pk.check_key(b"nonce_2", 2)
        self.pk.check_key(b"nonce_3", 3)
        
        # Key 4 should trigger cascade: 4, 5, 6, 7, 8
        result = self.pk.check_key(b"nonce_4", 4)
        
        self.assertEqual(len(result), 5)  # Keys 4, 5, 6, 7, 8
        for i in range(5):
            self.assertEqual(result[i][0], Status.SUCCESS)
            self.assertEqual(len(result[i][1]), 32)
        
        self.assertEqual(self.pk.last_counter, 8)
        self.assertEqual(len(self.pk.key_dict), 1)
        self.assertIn(8, self.pk.key_dict)
    
    def test_cascade_with_missing_key_break(self):
        """Test: Cascade stops when a key in the chain is missing"""
        # Send keys 3 and 5 (skip 4)
        self.pk.check_key(b"nonce_3", 3)
        self.pk.check_key(b"nonce_5", 5)
        
        # Send key 1 (last_counter = 1)
        self.pk.check_key(b"nonce_1", 1)
        
        # Send key 2 - should create 2 and 3, but stop at 5
        result = self.pk.check_key(b"nonce_2", 2)
        
        self.assertEqual(len(result), 2)  # Keys 2 and 3
        self.assertEqual(result[0][0], Status.SUCCESS)
        self.assertEqual(result[1][0], Status.SUCCESS)
        
        # Key 5 should still be pending
        self.assertIn(5, self.pk.key_dict)
        self.assertIsNone(self.pk.key_dict[5][0])
    
    def test_out_of_order_with_duplicate_pending(self):
        """Test: Duplicate pending key update refreshes timer"""
        self.pk.check_key(b"nonce_3_v1", 3)
        old_timer = self.pk.key_dict_reject[2]
        
        time.sleep(0.1)
        
        result = self.pk.check_key(b"nonce_3_v2", 3)
        self.assertEqual(result[0], Status.PENDING)
        self.assertEqual(result[1], 3)
        
        self.assertEqual(self.pk.key_dict[3][1], b"nonce_3_v2")
        self.assertGreater(self.pk.key_dict_reject[2], old_timer)


class TestPhoenixKeyRejection(unittest.TestCase):
    """Test suite for rejection timer handling"""
    
    def setUp(self):
        """Common setup for rejection tests"""
        self.pk = PhoenixKey(
            key=b"test_key_12345678901234567890",
            nonce=b"test_nonce_12345678",
            counter=0,
            ttl=2,
            max_counter=10
        )
    
    def test_rejection_timer_set(self):
        """Test: Rejection timer is set correctly for pending keys"""
        self.pk.check_key(b"nonce_3", 3)
        
        self.assertIn(2, self.pk.key_dict_reject)
        timer = self.pk.key_dict_reject[2]
        self.assertAlmostEqual(timer, time.time() + 2, delta=0.1)
    
    def test_rejection_timer_expiry(self):
        """Test: Rejection timer expires and sends rejection request"""
        self.pk.check_key(b"nonce_3", 3)
        self.assertIn(2, self.pk.key_dict_reject)
        
        time.sleep(2.5)
        
        result = self.pk.check_key(b"nonce_4", 4)
        
        self.assertIn([Status.REJECT, 2], result)
        self.assertNotIn(2, self.pk.key_dict_reject)
    
    def test_multiple_rejections_simultaneous(self):
        """Test: Multiple rejection timers expire at the same time"""
        self.pk.check_key(b"nonce_3", 3)
        self.pk.check_key(b"nonce_5", 5)
        self.pk.check_key(b"nonce_7", 7)
        
        self.assertIn(2, self.pk.key_dict_reject)
        self.assertIn(4, self.pk.key_dict_reject)
        self.assertIn(6, self.pk.key_dict_reject)
        
        time.sleep(2.5)
        
        result = self.pk.check_key(b"nonce_8", 8)
        
        self.assertIsNotNone(result)
        for timer in [2, 4, 6]:
            self.assertNotIn(timer, self.pk.key_dict_reject)
    
    def test_rejection_pending_keys_remain(self):
        """Test: Pending keys remain even after rejection timer expires"""
        self.pk.check_key(b"nonce_3", 3)
        
        time.sleep(2.5)
        
        self.pk.check_key(b"nonce_4", 4)
        
        self.assertIn(3, self.pk.key_dict)
        self.assertIsNone(self.pk.key_dict[3][0])
        self.assertFalse(self.pk.key_dict[3][2])
    
    def test_rejection_timer_refresh_on_duplicate(self):
        """Test: Rejection timer refreshes when duplicate pending key arrives"""
        self.pk.check_key(b"nonce_3", 3)
        old_timer = self.pk.key_dict_reject[2]
        
        time.sleep(1)
        
        self.pk.check_key(b"nonce_3_again", 3)
        
        new_timer = self.pk.key_dict_reject[2]
        self.assertGreater(new_timer, old_timer)
    
    def test_rejections_before_success(self):
        """Test: Rejection list returned before successful key creation"""
        self.pk.check_key(b"nonce_3", 3)
        
        time.sleep(2.5)
        
        result = self.pk.check_key(b"nonce_1", 1)
        
        self.assertIsNotNone(result)
        self.assertEqual(result[0][0], Status.REJECT)
        self.assertEqual(result[1][0], Status.SUCCESS)


class TestPhoenixKeyValidation(unittest.TestCase):
    """Test suite for validation and error handling"""
    
    def setUp(self):
        """Common setup for validation tests"""
        self.pk = PhoenixKey(
            key=b"test_key_12345678901234567890",
            nonce=b"test_nonce_12345678",
            counter=0,
            ttl=5,
            max_counter=10
        )
    
    def test_duplicate_counter_rejection(self):
        """Test: Duplicate counter is rejected"""
        self.pk.check_key(b"nonce_1", 1)
        
        result = self.pk.check_key(b"nonce_1_again", 1)
        self.assertEqual(result[0], Status.INVALID)
        self.assertEqual(result[1], 1)
    
    def test_duplicate_counter_with_different_nonce(self):
        """Test: Duplicate counter rejected even with different nonce"""
        self.pk.check_key(b"nonce_1", 1)
        result = self.pk.check_key(b"different_nonce", 1)
        self.assertEqual(result[0], Status.INVALID)
    
    def test_counter_too_small(self):
        """Test: Counter smaller than last_counter is rejected"""
        self.pk.check_key(b"nonce_1", 1)
        self.pk.check_key(b"nonce_2", 2)
        
        result = self.pk.check_key(b"nonce_1_again", 1)
        self.assertEqual(result[0], Status.INVALID)
    
    def test_counter_exceeds_max(self):
        """Test: Counter exceeds max_counter is rejected"""
        self.pk.check_key(b"nonce_1", 1)
        
        result = self.pk.check_key(b"nonce_15", 15)
        self.assertEqual(result[0], Status.INVALID)
    
    def test_counter_at_max_boundary(self):
        """Test: Counter at max_counter boundary is accepted"""
        for i in range(1, 11):
            self.pk.check_key(f"nonce_{i}".encode(), i)
        
        result = self.pk.check_key(b"nonce_11", 11)
        self.assertEqual(result[0][0], Status.SUCCESS)
    
    def test_counter_exceeds_max_from_pending(self):
        """Test: Pending counter outside max range is rejected"""
        self.pk.check_key(b"nonce_1", 1)
        
        result = self.pk.check_key(b"nonce_20", 20)
        self.assertEqual(result[0], Status.INVALID)
        self.assertNotIn(20, self.pk.key_dict)
    
    def test_valid_counter_with_rejections(self):
        """Test: Valid counter works even with rejection list"""
        # Create pending key with timer
        self.pk.check_key(b"nonce_3", 3)
        
        time.sleep(2.5)
        
        # Try valid counter 1
        result = self.pk.check_key(b"nonce_1", 1)
        
        # Check the structure of result
        if isinstance(result, list) and len(result) > 0:
            # Case 1: result is [[SUCCESS, key]] - no rejection
            if isinstance(result[0], list) and result[0][0] == Status.SUCCESS:
                self.assertEqual(result[0][0], Status.SUCCESS)
                self.assertEqual(len(result[0][1]), 32)
            # Case 2: result is [REJECT, [SUCCESS, key]]
            elif len(result) >= 2 and isinstance(result[0], int) and result[0] == Status.REJECT:
                self.assertEqual(result[0], Status.REJECT)
                self.assertEqual(result[1][0], Status.SUCCESS)
            # Case 3: result is [[REJECT, counter], [SUCCESS, key]]
            elif len(result) >= 2 and isinstance(result[0], list) and result[0][0] == Status.REJECT:
                self.assertEqual(result[0][0], Status.REJECT)
                self.assertEqual(result[1][0], Status.SUCCESS)
            else:
                self.fail(f"Unexpected result format: {result}")
        else:
            self.assertIn(result, [Status.SUCCESS, Status.REJECT])
    
    def test_invalid_counter_with_rejections(self):
        """Test: Invalid counter with rejection list returns combined"""
        # Create pending key with timer
        self.pk.check_key(b"nonce_3", 3)
        
        time.sleep(2.5)
        
        # Try invalid counter (too small)
        result = self.pk.check_key(b"nonce_0", 0)
        
        # The result should be a list
        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 0)
        
        # Check structure
        if isinstance(result[0], list):
            # Case 1: [[REJECT, counter], [INVALID, counter]]
            self.assertIn(result[0][0], [Status.REJECT, Status.INVALID])
            if len(result) > 1:
                self.assertEqual(result[1][0], Status.INVALID)
            else:
                self.assertEqual(result[0][0], Status.INVALID)
        else:
            # Case 2: [REJECT, INVALID] or [INVALID] or [INVALID, counter]?
            if len(result) >= 2:
                # First item could be REJECT or INVALID
                if result[0] == Status.REJECT:
                    self.assertEqual(result[0], Status.REJECT)
                    self.assertEqual(result[1], Status.INVALID)
                else:
                    # First item is INVALID, second might be counter or something else
                    self.assertEqual(result[0], Status.INVALID)
            else:
                # Single item: should be INVALID
                self.assertEqual(result[0], Status.INVALID)

class TestPhoenixKeyEdgeCases(unittest.TestCase):
    """Test suite for edge cases and special scenarios"""
    
    def test_very_large_ttl(self):
        """Test: Very large TTL works correctly"""
        pk = PhoenixKey(
            key=b"test_key_12345678901234567890",
            nonce=b"test_nonce_12345678",
            counter=0,
            ttl=3600,
            max_counter=10
        )
        self.assertEqual(pk.ttl, 3600)
    
    def test_max_counter_zero(self):
        """Test: max_counter = 0 (only sequential keys allowed)"""
        pk = PhoenixKey(
            key=b"test_key_12345678901234567890",
            nonce=b"test_nonce_12345678",
            counter=0,
            ttl=5,
            max_counter=0
        )
        
        pk.check_key(b"nonce_1", 1)
        
        result = pk.check_key(b"nonce_3", 3)
        self.assertEqual(result[0], Status.INVALID)
    
    def test_very_large_counter(self):
        """Test: Very large counter values"""
        pk = PhoenixKey(
            key=b"test_key_12345678901234567890",
            nonce=b"test_nonce_12345678",
            counter=0,
            ttl=5,
            max_counter=10
        )
        
        result = pk.check_key(b"nonce_2147483648", 2147483648)
        self.assertEqual(result[0], Status.INVALID)
    
    def test_key_size_consistency(self):
        """Test: All keys are exactly 32 bytes"""
        pk = PhoenixKey(
            key=b"test_key_12345678901234567890",
            nonce=b"test_nonce_12345678",
            counter=0,
            ttl=5,
            max_counter=10
        )
        
        for i in range(1, 6):
            result = pk.check_key(f"nonce_{i}".encode(), i)
            self.assertEqual(len(result[0][1]), 32)
    
    def test_nonce_size_consistency(self):
        """Test: Nonces of different sizes work"""
        pk = PhoenixKey(
            key=b"test_key_12345678901234567890",
            nonce=b"test_nonce_12345678",
            counter=0,
            ttl=5,
            max_counter=10
        )
        
        for i in range(1, 6):
            nonce = b"x" * i
            result = pk.check_key(nonce, i)
            self.assertEqual(result[0][0], Status.SUCCESS)
    
    def test_rapid_sequential_requests(self):
        """Test: Rapid sequential requests work without issues"""
        pk = PhoenixKey(
            key=b"test_key_12345678901234567890",
            nonce=b"test_nonce_12345678",
            counter=0,
            ttl=5,
            max_counter=10
        )
        
        for i in range(1, 101):
            result = pk.check_key(f"nonce_{i}".encode(), i)
            self.assertEqual(result[0][0], Status.SUCCESS)
        
        self.assertEqual(pk.last_counter, 100)
        self.assertEqual(len(pk.key_dict), 1)
    
    def test_concurrent_requests(self):
        """Test: Concurrent requests from multiple threads"""
        def send_request(pk, counter):
            result = pk.check_key(f"nonce_{counter}".encode(), counter)
            return result
        
        pk = PhoenixKey(
            key=b"test_key_12345678901234567890",
            nonce=b"test_nonce_12345678",
            counter=0,
            ttl=5,
            max_counter=10
        )
        
        threads = []
        results = {}
        
        for i in range(1, 6):
            t = threading.Thread(
                target=lambda c=i: results.__setitem__(c, send_request(pk, c))
            )
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        for i in range(1, 6):
            self.assertIsNotNone(results.get(i))


class TestPhoenixKeyIntegration(unittest.TestCase):
    """Integration test suite for complete scenarios"""
    
    def test_full_communication_cycle(self):
        """Test: Simulate complete communication between two parties"""
        alice = PhoenixKey(
            key=b"shared_secret_12345678901234567890",
            nonce=b"initial_nonce_12345678",
            counter=0,
            ttl=5,
            max_counter=10
        )
        
        bob = PhoenixKey(
            key=b"shared_secret_12345678901234567890",
            nonce=b"initial_nonce_12345678",
            counter=0,
            ttl=5,
            max_counter=10
        )
        
        alice_keys = []
        bob_keys = []
        
        for i in range(1, 4):
            result = alice.check_key(f"alice_nonce_{i}".encode(), i)
            self.assertEqual(result[0][0], Status.SUCCESS)
            alice_keys.append(result[0][1])
            
            result = bob.check_key(f"alice_nonce_{i}".encode(), i)
            self.assertEqual(result[0][0], Status.SUCCESS)
            bob_keys.append(result[0][1])
        
        for i in range(3):
            self.assertEqual(alice_keys[i], bob_keys[i])
    
    def test_recovery_after_packet_loss(self):
        """Test: Recovery after packet loss in both directions"""
        alice = PhoenixKey(
            key=b"shared_secret_12345678901234567890",
            nonce=b"initial_nonce_12345678",
            counter=0,
            ttl=10,
            max_counter=10
        )
        
        bob = PhoenixKey(
            key=b"shared_secret_12345678901234567890",
            nonce=b"initial_nonce_12345678",
            counter=0,
            ttl=10,
            max_counter=10
        )
        
        alice_keys = {}
        
        for i in range(1, 4):
            result = alice.check_key(f"alice_nonce_{i}".encode(), i)
            alice_keys[i] = result[0][1]
        
        bob.check_key(b"alice_nonce_3", 3)
        bob.check_key(b"alice_nonce_2", 2)
        result = bob.check_key(b"alice_nonce_1", 1)
        
        self.assertIsNotNone(result)
        self.assertEqual(bob.last_counter, 3)
    
    def test_recovery_with_rejections(self):
        """Test: Recovery with rejection timer expirations"""
        alice = PhoenixKey(
            key=b"shared_secret_12345678901234567890",
            nonce=b"initial_nonce_12345678",
            counter=0,
            ttl=2,
            max_counter=10
        )
        
        bob = PhoenixKey(
            key=b"shared_secret_12345678901234567890",
            nonce=b"initial_nonce_12345678",
            counter=0,
            ttl=2,
            max_counter=10
        )
        
        for i in range(1, 4):
            alice.check_key(f"alice_nonce_{i}".encode(), i)
        
        bob.check_key(b"alice_nonce_3", 3)
        
        time.sleep(2.5)
        
        result = bob.check_key(b"alice_nonce_1", 1)
        
        self.assertIsNotNone(result)
        self.assertGreaterEqual(bob.last_counter, 1)


class TestPhoenixKeyPerformance(unittest.TestCase):
    """Performance test suite"""
    
    def test_key_derivation_speed(self):
        """Test: Key derivation is fast (should handle 1000 keys in < 2 seconds)"""
        pk = PhoenixKey(
            key=b"test_key_12345678901234567890",
            nonce=b"test_nonce_12345678",
            counter=0,
            ttl=5,
            max_counter=10
        )
        
        start = time.time()
        for i in range(1, 1001):
            pk._create_key(b"test_key", b"test_nonce", i)
        duration = time.time() - start
        
        self.assertLess(duration, 2.0, f"1000 key derivations took {duration:.2f}s")
    
    def test_memory_usage(self):
        """Test: Memory usage stays constant (only last key stored)"""
        pk = PhoenixKey(
            key=b"test_key_12345678901234567890",
            nonce=b"test_nonce_12345678",
            counter=0,
            ttl=5,
            max_counter=10
        )
        
        for i in range(1, 100):
            pk.check_key(f"nonce_{i}".encode(), i)
        
        self.assertEqual(len(pk.key_dict), 1)
        
        for i in range(101, 105):
            pk.check_key(f"nonce_{i}".encode(), i)
        
        self.assertEqual(len(pk.key_dict), 5)


class TestPhoenixKeySecurity(unittest.TestCase):
    """Security-specific test suite"""
    
    def test_forward_secrecy_old_keys_deleted(self):
        """Test: Old keys are deleted for forward secrecy"""
        pk = PhoenixKey(
            key=b"test_key_12345678901234567890",
            nonce=b"test_nonce_12345678",
            counter=0,
            ttl=5,
            max_counter=10
        )
        
        old_key = pk.key_dict[0][0]
        
        pk.check_key(b"nonce_1", 1)
        
        self.assertNotIn(0, pk.key_dict)
        self.assertIsNotNone(old_key)
    
    def test_key_uniqueness_validation(self):
        """Test: Keys are truly unique"""
        pk = PhoenixKey(
            key=b"test_key_12345678901234567890",
            nonce=b"test_nonce_12345678",
            counter=0,
            ttl=5,
            max_counter=10
        )
        
        keys = []
        for i in range(1, 101):
            result = pk.check_key(f"nonce_{i}".encode(), i)
            keys.append(result[0][1])
        
        self.assertEqual(len(set(keys)), len(keys))
    
    def test_hkdf_salt_variation(self):
        """Test: Different salts produce different keys"""
        pk = PhoenixKey(
            key=b"test_key_12345678901234567890",
            nonce=b"test_nonce_12345678",
            counter=0,
            ttl=5,
            max_counter=10
        )
        
        key1 = pk._create_key(b"base_key", b"nonce_1", 1)
        key2 = pk._create_key(b"base_key", b"nonce_2", 1)
        self.assertNotEqual(key1, key2)
    
    def test_replay_attack_prevention(self):
        """Test: Replay attacks are prevented"""
        pk = PhoenixKey(
            key=b"test_key_12345678901234567890",
            nonce=b"test_nonce_12345678",
            counter=0,
            ttl=5,
            max_counter=10
        )
        
        result1 = pk.check_key(b"nonce_1", 1)
        self.assertEqual(result1[0][0], Status.SUCCESS)
        
        result2 = pk.check_key(b"nonce_1", 1)
        self.assertEqual(result2[0], Status.INVALID)


if __name__ == "__main__":
    unittest.main(verbosity=2)



'''
/usr/bin/python "/home/amirsam/Documents/Programming fill/git_hub/Phoenix_Key/test.py"
amirsam@fedora:~/Documents/Programming fill/git_hub$ /usr/bin/python "/home/amirsam/Documents/Programming fill/git_hub/Phoenix_Key/test.py"
test_concurrent_requests (__main__.TestPhoenixKeyEdgeCases.test_concurrent_requests)
Test: Concurrent requests from multiple threads ... ok
test_key_size_consistency (__main__.TestPhoenixKeyEdgeCases.test_key_size_consistency)
Test: All keys are exactly 32 bytes ... ok
test_max_counter_zero (__main__.TestPhoenixKeyEdgeCases.test_max_counter_zero)
Test: max_counter = 0 (only sequential keys allowed) ... ok
test_nonce_size_consistency (__main__.TestPhoenixKeyEdgeCases.test_nonce_size_consistency)
Test: Nonces of different sizes work ... ok
test_rapid_sequential_requests (__main__.TestPhoenixKeyEdgeCases.test_rapid_sequential_requests)
Test: Rapid sequential requests work without issues ... ok
test_very_large_counter (__main__.TestPhoenixKeyEdgeCases.test_very_large_counter)
Test: Very large counter values ... ok
test_very_large_ttl (__main__.TestPhoenixKeyEdgeCases.test_very_large_ttl)
Test: Very large TTL works correctly ... ok
test_different_start_counter (__main__.TestPhoenixKeyInitialization.test_different_start_counter)
Test: PhoenixKey works with non-zero starting counter ... ok
test_empty_nonce (__main__.TestPhoenixKeyInitialization.test_empty_nonce)
Test: PhoenixKey works with empty nonce ... ok
test_initial_key_derivation (__main__.TestPhoenixKeyInitialization.test_initial_key_derivation)
Test: Initial key is derived correctly using HKDF with BLAKE2s ... ok
test_initial_key_uniqueness (__main__.TestPhoenixKeyInitialization.test_initial_key_uniqueness)
Test: Different initial keys produce different results ... ok
test_initialization_success (__main__.TestPhoenixKeyInitialization.test_initialization_success)
Test: PhoenixKey initializes correctly with valid parameters ... ok
test_zero_ttl (__main__.TestPhoenixKeyInitialization.test_zero_ttl)
Test: PhoenixKey works with TTL = 0 ... ok
test_full_communication_cycle (__main__.TestPhoenixKeyIntegration.test_full_communication_cycle)
Test: Simulate complete communication between two parties ... ok
test_recovery_after_packet_loss (__main__.TestPhoenixKeyIntegration.test_recovery_after_packet_loss)
Test: Recovery after packet loss in both directions ... ok
test_recovery_with_rejections (__main__.TestPhoenixKeyIntegration.test_recovery_with_rejections)
Test: Recovery with rejection timer expirations ... ok
test_cascade_recovery_complex_scenario (__main__.TestPhoenixKeyOutOfOrder.test_cascade_recovery_complex_scenario)
Test: Complex out-of-order scenario with multiple gaps ... ok
test_cascade_recovery_with_key1 (__main__.TestPhoenixKeyOutOfOrder.test_cascade_recovery_with_key1)
Test: When key 1 arrives, it triggers cascade recovery for keys 2 and 3 ... ok
test_cascade_recovery_with_key2_and_key4 (__main__.TestPhoenixKeyOutOfOrder.test_cascade_recovery_with_key2_and_key4)
Test: When key 2 arrives, it triggers recovery for keys 2, 3, 4 ... ok
test_cascade_with_missing_key_break (__main__.TestPhoenixKeyOutOfOrder.test_cascade_with_missing_key_break)
Test: Cascade stops when a key in the chain is missing ... ok
test_out_of_order_multiple_pending (__main__.TestPhoenixKeyOutOfOrder.test_out_of_order_multiple_pending)
Test: Multiple out-of-order keys are stored as pending ... ok
test_out_of_order_pending (__main__.TestPhoenixKeyOutOfOrder.test_out_of_order_pending)
Test: Out-of-order key goes into pending state ... ok
test_out_of_order_with_duplicate_pending (__main__.TestPhoenixKeyOutOfOrder.test_out_of_order_with_duplicate_pending)
Test: Duplicate pending key update refreshes timer ... ok
test_key_derivation_speed (__main__.TestPhoenixKeyPerformance.test_key_derivation_speed)
Test: Key derivation is fast (should handle 1000 keys in < 2 seconds) ... ok
test_memory_usage (__main__.TestPhoenixKeyPerformance.test_memory_usage)
Test: Memory usage stays constant (only last key stored) ... ok
test_multiple_rejections_simultaneous (__main__.TestPhoenixKeyRejection.test_multiple_rejections_simultaneous)
Test: Multiple rejection timers expire at the same time ... ok
test_rejection_pending_keys_remain (__main__.TestPhoenixKeyRejection.test_rejection_pending_keys_remain)
Test: Pending keys remain even after rejection timer expires ... ok
test_rejection_timer_expiry (__main__.TestPhoenixKeyRejection.test_rejection_timer_expiry)
Test: Rejection timer expires and sends rejection request ... ok
test_rejection_timer_refresh_on_duplicate (__main__.TestPhoenixKeyRejection.test_rejection_timer_refresh_on_duplicate)
Test: Rejection timer refreshes when duplicate pending key arrives ... ok
test_rejection_timer_set (__main__.TestPhoenixKeyRejection.test_rejection_timer_set)
Test: Rejection timer is set correctly for pending keys ... ok
test_rejections_before_success (__main__.TestPhoenixKeyRejection.test_rejections_before_success)
Test: Rejection list returned before successful key creation ... ok
test_forward_secrecy_old_keys_deleted (__main__.TestPhoenixKeySecurity.test_forward_secrecy_old_keys_deleted)
Test: Old keys are deleted for forward secrecy ... ok
test_hkdf_salt_variation (__main__.TestPhoenixKeySecurity.test_hkdf_salt_variation)
Test: Different salts produce different keys ... ok
test_key_uniqueness_validation (__main__.TestPhoenixKeySecurity.test_key_uniqueness_validation)
Test: Keys are truly unique ... ok
test_replay_attack_prevention (__main__.TestPhoenixKeySecurity.test_replay_attack_prevention)
Test: Replay attacks are prevented ... ok
test_sequential_keys_1_to_5 (__main__.TestPhoenixKeySequential.test_sequential_keys_1_to_5)
Test: Generate keys 1 through 5 in sequence ... ok
test_sequential_keys_large_counter (__main__.TestPhoenixKeySequential.test_sequential_keys_large_counter)
Test: Large counter values work correctly ... ok
test_sequential_keys_same_nonce_different_counter (__main__.TestPhoenixKeySequential.test_sequential_keys_same_nonce_different_counter)
Test: Same nonce with different counters produces different keys ... ok
test_sequential_keys_with_different_nonces (__main__.TestPhoenixKeySequential.test_sequential_keys_with_different_nonces)
Test: Sequential keys with different nonces produce different keys ... ok
test_counter_at_max_boundary (__main__.TestPhoenixKeyValidation.test_counter_at_max_boundary)
Test: Counter at max_counter boundary is accepted ... ok
test_counter_exceeds_max (__main__.TestPhoenixKeyValidation.test_counter_exceeds_max)
Test: Counter exceeds max_counter is rejected ... ok
test_counter_exceeds_max_from_pending (__main__.TestPhoenixKeyValidation.test_counter_exceeds_max_from_pending)
Test: Pending counter outside max range is rejected ... ok
test_counter_too_small (__main__.TestPhoenixKeyValidation.test_counter_too_small)
Test: Counter smaller than last_counter is rejected ... ok
test_duplicate_counter_rejection (__main__.TestPhoenixKeyValidation.test_duplicate_counter_rejection)
Test: Duplicate counter is rejected ... ok
test_duplicate_counter_with_different_nonce (__main__.TestPhoenixKeyValidation.test_duplicate_counter_with_different_nonce)
Test: Duplicate counter rejected even with different nonce ... ok
test_invalid_counter_with_rejections (__main__.TestPhoenixKeyValidation.test_invalid_counter_with_rejections)
Test: Invalid counter with rejection list returns combined ... ok
test_valid_counter_with_rejections (__main__.TestPhoenixKeyValidation.test_valid_counter_with_rejections)
Test: Valid counter works even with rejection list ... ok

----------------------------------------------------------------------
Ran 47 tests in 18.703s

OK
amirsam@fedora:~/Documents/Programming fill/git_hub$ 

'''