import pytest

from assemblyline.common.exceptions import Chain, ChainAll


class CustomError(ValueError):
    pass


@Chain(CustomError)
def fail_function():
    raise Exception()


@ChainAll(CustomError)
class FailClass:
    def fail_method(self):
        raise Exception()

    @staticmethod
    def static_fail_method():
        raise Exception()


def test_exception_chaining():
    with pytest.raises(CustomError):
        fail_function()

    with pytest.raises(CustomError):
        FailClass().fail_method()

    with pytest.raises(CustomError):
        FailClass.static_fail_method()

