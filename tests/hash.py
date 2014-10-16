import unittest

from fsisketch.hash import *

class TestHash(unittest.TestCase):
    def test_buckets(self):
        self.assertEqual(list(buckets(b'abcdef', 10, 1000)), 
                [813, 1313, 2676, 3536, 4790, 5747, 6200, 7840, 8803, 9446])

