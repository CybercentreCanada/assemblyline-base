# cython: language_level=3

# noinspection PyUnresolvedReferences
from libc.string cimport memset

def counts(b, c, d=None):
    if d is None:
        d = {}
    cdef long long t[256]
    cdef unsigned char* s = b
    cdef int l = c
    cdef int i = 0

    memset(t, 0, 256 * sizeof(long long))

    for k, v in d.iteritems():
        t[k] = v

    while i < l:
        t[s[i]] += 1
        i += 1

    return {i: t[i] for i in range(256) if t[i]}

def counts_old(s, d=None):
    if d is None:
        d = {}
    cdef int i
    cdef int t[256]

    memset(t, 0, 256 * sizeof(int))

    for k, v in d.iteritems():
        t[k] = v

    for c in s:
        t[ord(c)] += 1

    return {i: t[i] for i in range(256) if t[i]}
