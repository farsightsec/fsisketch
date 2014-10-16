import unittest

from fsisketch.hash import *

class TestHash(unittest.TestCase):
    def test_buckets(self):
        self.assertEqual(list(buckets('abcdef', 10, 1000)), 
                [429, 1537, 2477, 3633, 4237, 5441, 6093, 7961, 8045, 9577])

