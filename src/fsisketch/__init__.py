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

from fsisketch.bloom_calculations import max_buckets_per_element, compute_bloom_spec
import fsisketch.hash
import mmaparray

import six

class Sketch(object):
    def __init__(self, filename, typecode, size, fp_prob=0.001, seed=0, read_only=False, want_lock=False):
        self._seed = seed

        buckets_per_element = max_buckets_per_element(size)
        K, buckets_per_element = compute_bloom_spec(buckets_per_element, fp_prob)

        self._num_rows = K
        self._row_size = int(size * buckets_per_element / self._num_rows)
        self._backing = mmaparray.array(filename, typecode,
                self._row_size * self._num_rows, read_only, want_lock)

    def clear(self):
        for i in range(0, len(self._backing)):
            self._backing[i] = 0

    def _buckets(self, key):
        if not isinstance(key, six.binary_type):
            key = six.b(key)
        return fsisketch.hash.buckets(key, self._num_rows, self._row_size)

    def __setitem__(self, key, value):
        raise NotImplementedError()

    def __getitem__(self, key):
        raise NotImplementedError()

    def __contains__(self, key):
        return bool(self[key])

    def add(self, key, count=1):
        raise NotImplementedError()

    def remove(self, key, count=1):
        raise NotImplementedError()

    def discard(self, key, count=1):
        if self[key] >= count:
            self.remove(key, count)

    def intersection(self, s):
        return [v for v in s if v in self]

    def isdisjoint(self, s):
        return len(self.intersection(s)) == 0

    def issuperset(self, s):
        for v in s:
            if v not in self:
                return False
        return True

    def intersection_update(self, s):
        for v in self.intersection(s):
            self.add(v)

    def difference(self, s):
        return [v for v in s if v not in self]

    def difference_update(self, s):
        for v in s:
            self.discard(v)

    def update(self, *args):
        for s in args:
            if isinstance(s, CMSketch):
                if len(self._backing) != len(s._backing):
                    raise ValueError ('Cannot update sketches with different sizes. {} != {}'.format(len(self._backing), len(s._backing)))

                for i in range(0, len(self._backing)):
                    self._backing[i] += s._backing[i]
            else:
                for v in s:
                    self.add(v)

class CMSketch(Sketch):
    def __init__(self, filename, typecode, size, fp_prob=0.001, seed=0, read_only=False, want_lock=False):
        super(CMSketch, self).__init__(filename, typecode, size, fp_prob, seed, read_only, want_lock)

        if typecode in 'o':
            raise ValueError("Unsupported type code: '{}'".format(typecode))


    def __setitem__(self, key, value):
        for i in self._buckets(key):
            self._backing[i] = value

    def __getitem__(self, key):
        return min(self._backing[i] for i in self._buckets(key))

    def add(self, key, count=1):
        for i in self._buckets(key):
            self._backing[i] += count

    def remove(self, key, count=1):
        self.add(key, -count)
