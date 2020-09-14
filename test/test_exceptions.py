import pytest

from assemblyline.common.exceptions import Chain, ChainAll, ChainException


class CustomError(ChainException):
    pass


@Chain(CustomError)
def fail_function(message):
    raise Exception(message)


@ChainAll(CustomError)
class FailClass:
    def fail_method(self):
        raise Exception()

    @staticmethod
    def static_fail_method():
        raise Exception()


def test_exception_chaining():
    with pytest.raises(CustomError) as error_info:
        fail_function('abc123')
    assert isinstance(error_info.value.cause, Exception)
    assert error_info.value.cause.args[0] == 'abc123'

    with pytest.raises(CustomError):
        FailClass().fail_method()

    with pytest.raises(CustomError):
        FailClass.static_fail_method()

