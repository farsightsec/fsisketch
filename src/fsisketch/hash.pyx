#cython: embedsignature=True

from libc.stdint cimport *

import mmh3

def buckets(key, size_t n, size_t row_size, int64_t seed=0):
    cdef int64_t h1, h2
    cdef size_t i

    (h1, h2) = mmh3.hash64(key, seed=seed)

    for i in range(0, n):
        yield (h1 + i**2 * h2) % row_size + i * row_size
