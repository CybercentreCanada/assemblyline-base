"""
This test is to verify that we can import and call functions that should be cython-ized during installation
of the assemblyline package.
"""


def test_frequency_call():
    from assemblyline.common import frequency
    table = frequency.counts(b'abcc', 5)
    assert table == {ord('a'): 1, ord('b'): 1, ord('c'): 2}
    table = frequency.counts(b'abcc', 2)
    assert table == {ord('a'): 1, ord('b'): 1}
