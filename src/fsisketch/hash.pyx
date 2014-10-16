#cython: embedsignature=True

from libc.stdint cimport *

cdef extern from "MurmurHash3.h" nogil:
    void MurmurHash3_x64_128 (char * key, int len, uint32_t seed, int64_t * out)

def buckets(bytes key, int64_t n, int64_t row_size, uint32_t seed=0):
    cdef int64_t result[2]
    cdef int64_t i

    for i in range(0, n):
        MurmurHash3_x64_128(key, len(key), seed, result)
        seed = result[1]
        yield result[0] % row_size + i * row_size
