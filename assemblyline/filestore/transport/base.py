from typing import AnyStr, Iterable, Optional

from assemblyline.common.exceptions import ChainException


def normalize_srl_path(srl):
    if '/' in srl:
        return srl

    return '{0}/{1}/{2}/{3}/{4}'.format(srl[0], srl[1], srl[2], srl[3], srl)


class TransportException(ChainException):
    """
    FileTransport exception base class.

    TransportException is a subclass of ChainException so that it can be
    used with the Chain and ChainAll decorators.
    """
    pass


class Transport(object):
    """
    FileTransport base class.

    - Subclasses should override all methods.
    - Except as noted, FileTransport methods do not return value and raise
    - TransportException on failure.
    - Methods should only raise TransportExceptions. (The decorators
      Chain and ChainAll can be applied to a function/method and class,
      respectively, to ensure that any exceptions raised are converted to
      TransportExceptions.
    """

    def __init__(self, normalize=normalize_srl_path):
        self.normalize = normalize

    def close(self):
        pass

    def delete(self, path: str):
        """
        Deletes the file.
        """
        raise TransportException("Not Implemented")

    def exists(self, path: str) -> bool:
        """
        Returns True if the path exists, False otherwise.
        Should work with both files and directories.
        """
        raise TransportException("Not Implemented")

    def makedirs(self, path: str):
        """
        Like os.makedirs the super-mkdir, create the leaf directory path and
        any intermediate path segments.
        """
        raise TransportException("Not Implemented")

    # File based functions
    def download(self, src_path: str, dst_path: str):
        """
        Copies the content of the filestore src_path to the local dst_path.
        """
        raise TransportException("Not Implemented")

    def upload(self, src_path: str, dst_path: str):
        """
        Save upload source file src_path to to the filesotre dst_path, overwriting dst_path if it already exists.
        """
        raise TransportException("Not Implemented")

    # Buffer based functions
    def get(self, path: str) -> bytes:
        """
        Returns the content of the file.
        """
        raise TransportException("Not Implemented")

    def put(self, dst_path: str, content: AnyStr):
        """
        Put the content of the file in memory directly to the filestore dst_path
        """
        raise TransportException("Not Implemented")

    def list(self, prefix: Optional[str] = None) -> Iterable[str]:
        """List all files in the store filtered by name prefix."""
        raise NotImplementedError()
