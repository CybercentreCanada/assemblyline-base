"""
Dummy functions used to substitute for dynamic loaded methods that
have no interesting implementation by default.
"""


def always_false(*args, **kwargs):
    return False
