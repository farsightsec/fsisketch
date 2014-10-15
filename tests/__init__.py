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

import tempfile
import unittest

from fsisketch import *

words = [line.rstrip() for line in open('/usr/share/dict/words')]

class TestCMSketch(unittest.TestCase):
    def setUp(self):
        self.backing = tempfile.NamedTemporaryFile(prefix='fsisketch_test')
        self.backing.file.close()

        self.sketch = CMSketch(self.backing.name, 'h', 500, fp_prob=1e-4)

    def test_buckets(self):
        self.assertEqual(list(self.sketch._buckets('abcdef')), 
                [621, 1537, 2285, 3865, 4277, 5521, 6597, 7505, 8245, 9817])

    def test_add(self):
        for w in words[:500]:
            self.assertNotIn(w, self.sketch)
            self.sketch.add(w)
            self.assertIn(w, self.sketch)

    def test_remove(self):
        for w in words[:500]:
            self.assertNotIn(w, self.sketch)
            self.sketch.add(w)
            self.assertIn(w, self.sketch)

        for w in words[:500]:
            c1 = self.sketch[w]
            self.sketch.remove(w)
            self.assertEqual(self.sketch[w], c1-1)

    def test_discard(self):
        for w in words[:500]:
            self.assertNotIn(w, self.sketch)

            self.sketch.discard(w)
            self.assertNotIn(w, self.sketch)

            self.sketch.add(w)
            self.assertIn(w, self.sketch)

            self.sketch.discard(w)
            self.assertNotIn(w, self.sketch)

    def test_clear(self):
        self.sketch.update(words[:500])
        self.sketch.clear()
        self.assertEqual(list(self.sketch.intersection(words[:500])), [])

    def test_update_contains_get(self):
        self.sketch.update(words[:500])

        for w in words[:500]:
            self.assertIn(w, self.sketch)
            self.assertGreater(self.sketch[w], 0)

    def test_intersection(self):
        self.sketch.update(words[:500])
        self.assertEqual(list(self.sketch.intersection(words[250:750])), words[250:500])

    def test_intersection_update(self):
        self.sketch.update(words[:500])
        for w in words[:20]:
            self.assertEqual(self.sketch[w], 1)
        self.sketch.intersection_update(words[:10])
        for w in words[:10]:
            self.assertEqual(self.sketch[w], 2)
        for w in words[10:20]:
            self.assertEqual(self.sketch[w], 1)

    def test_isdisjoint(self):
        self.sketch.update(words[:500])
        self.assertTrue(self.sketch.isdisjoint(words[500:1000]))
        self.assertFalse(self.sketch.isdisjoint(words[499:501]))

    def test_issuperset(self):
        self.sketch.update(words[:500])
        self.assertTrue(self.sketch.issuperset(words[250:500]))
        self.assertFalse(self.sketch.issuperset(words[250:501]))
        self.assertFalse(self.sketch.issuperset(words[500:501]))

    def test_difference(self):
        self.sketch.update(words[:500])
        self.assertEqual(list(self.sketch.difference(words[250:750])), words[500:750])

    def test_difference_update(self):
        self.sketch.update(words[10:500])
        for w in words[:10]:
            self.assertEqual(self.sketch[w], 0)
        for w in words[10:20]:
            self.assertEqual(self.sketch[w], 1)
        self.sketch.difference_update(words[:20])
        for w in words[:10]:
            self.assertEqual(self.sketch[w], 0)
        for w in words[10:20]:
            self.assertEqual(self.sketch[w], 0)
