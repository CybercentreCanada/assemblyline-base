"""
Testing methods used across different assemblyline repositories.
"""
import os

_possible_ci_variables = {
    'CI',  # Some CI systems set this to true
    'BITBUCKET_BUILD_NUMBER',  # Set to a monotonically increasing number under bitbucket
}


def skip(message):
    """Skip a test, but only if we aren't in a CI environment."""
    import pytest
    # Look at the environment, see if any suggestive variables are set
    if any(os.environ.get(name, False) for name in _possible_ci_variables):
        return pytest.fail(message)
    return pytest.skip(message)
