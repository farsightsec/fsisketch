# Copyright (c) 2014 by Farsight Security, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import unittest

from fsisketch.bloom_calculations import *
import six

class TestBloomCalculations(unittest.TestCase):
    def test_max_buckets_per_element(self):
        self.assertEqual(max_buckets_per_element(1), 20)
        for i in range(1, 20):
            self.assertEqual(max_buckets_per_element(six.MAXSIZE / i), i)

    def test_compute_bloom_spec(self):
        self.assertRaises(ValueError, compute_bloom_spec, 0, 0.01)
        self.assertRaises(ValueError, compute_bloom_spec, 21, 0.01)
        self.assertEqual(compute_bloom_spec(1, 0.4), (2, 1))
        self.assertRaises(ValueError, compute_bloom_spec, 1, 1e-20)

        # not sure about testing the rest
