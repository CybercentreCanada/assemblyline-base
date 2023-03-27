import logging
import os
import shutil
import re
from typing import AnyStr, Iterable, Optional

from assemblyline.common.exceptions import ChainAll
from assemblyline.common.path import strip_leading_inclusion
from assemblyline.common.uid import get_random_id
from assemblyline.filestore.transport.base import Transport, TransportException, normalize_srl_path

NORMALIZED = re.compile('[a-z0-9]/[a-z0-9]/[a-z0-9]/[a-z0-9]/[a-z0-9]{64}')


@ChainAll(TransportException)
class TransportLocal(Transport):
    """
    Local file system Transport class.
    """

    def __init__(self, base=None, normalize=None):
        self.log = logging.getLogger('assemblyline.transport.local')
        self.base = base
        self.host = "localhost"

        def local_normalize(path):
            # If they've provided an absolute path. Leave it a is.
            if path.startswith('/'):
                s = path
            # Relative paths
            elif '/' in path or len(path) != 64:
                s = _join(self.base, path)
            else:
                s = _join(self.base, normalize_srl_path(path))
            self.log.debug('local normalized: %s -> %s', path, s)
            return s

        if not normalize:
            normalize = local_normalize

        super(TransportLocal, self).__init__(normalize=normalize)

    def delete(self, path):
        normal_path = self.normalize(path)
        try:
            os.unlink(normal_path)
        except FileNotFoundError:
            pass
        except OSError as error:
            raise ValueError(f"Error erasing {path} as {normal_path}: {error}") from error

    def exists(self, path):
        path = self.normalize(path)
        return os.path.exists(path)

    def makedirs(self, path):
        path = self.normalize(path)
        try:
            os.makedirs(path)
        except OSError as e:
            if e.errno == 17:
                pass
            else:
                raise e

    # File based functions
    def download(self, src_path, dst_path):
        if src_path == dst_path:
            return

        src_path = self.normalize(src_path)
        dir_path = os.path.dirname(dst_path)
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)
        shutil.copy(src_path, dst_path)

    def upload(self, src_path, dst_path):
        dst_path = self.normalize(dst_path)
        if src_path == dst_path:
            return

        dirname = os.path.dirname(dst_path)
        filename = os.path.basename(dst_path)
        tempname = get_random_id()
        temppath = _join(dirname, tempname)
        finalpath = _join(dirname, filename)
        assert (finalpath == dst_path)
        self.makedirs(dirname)
        shutil.copy(src_path, temppath)
        shutil.move(temppath, finalpath)
        assert (self.exists(dst_path))

    # Buffer based functions
    def get(self, path: str) -> bytes:
        path = self.normalize(path)
        fh = None
        try:
            fh = open(path, "rb")
            return fh.read()
        finally:
            if fh:
                fh.close()

    def put(self, path: str, content: AnyStr):
        path = self.normalize(path)

        dirname = os.path.dirname(path)
        filename = os.path.basename(path)

        tempname = get_random_id()
        temppath = _join(dirname, tempname)

        finalpath = _join(dirname, filename)
        assert(finalpath == path)

        self.makedirs(dirname)
        fh = None
        try:
            fh = open(temppath, "wb")
            if isinstance(content, str):
                return fh.write(content.encode())
            else:
                return fh.write(content)
        finally:
            if fh:
                fh.close()

            try:
                shutil.move(temppath, finalpath)
            except shutil.Error:
                pass
            assert(self.exists(path))

    def __str__(self):
        return 'file://{}'.format(self.base)

    def _denormalize(self, name):
        if NORMALIZED.fullmatch(name):
            return name.split('/')[-1]
        return name

    def list(self, prefix: Optional[str] = None) -> Iterable[str]:
        for name in self._list(self.base, prefix, prefix):
            yield self._denormalize(name)

    def _list(self, path: str, dir_prefix: Optional[str], file_prefix: Optional[str]) -> Iterable[str]:
        for listed in os.listdir(path):
            listed_path = os.path.join(path, listed)
            if os.path.isdir(listed_path):
                if dir_prefix:
                    if listed.startswith(dir_prefix) or dir_prefix.startswith(listed):
                        for subfile in self._list(listed_path, dir_prefix[len(listed):], file_prefix):
                            yield os.path.join(listed, subfile)
                else:
                    for subfile in self._list(listed_path, None, file_prefix):
                        yield os.path.join(listed, subfile)
            if os.path.isfile(listed_path):
                if not file_prefix or listed.startswith(file_prefix) or not dir_prefix or listed.startswith(dir_prefix):
                    yield listed


###############################
# Helper functions.
###############################


def _join(base, path):
    path = path.replace("\\", "/").replace("//", "/")
    if base is None:
        return path
    return os.path.join(base, strip_leading_inclusion(path)).replace("\\", "/")
