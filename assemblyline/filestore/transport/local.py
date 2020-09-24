import logging
import os
import shutil

from assemblyline.common.exceptions import ChainAll
from assemblyline.common.uid import get_random_id
from assemblyline.filestore.transport.base import Transport, TransportException, normalize_srl_path, TransportFile


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
        path = self.normalize(path)
        os.unlink(path)

    def exists(self, path):
        path = self.normalize(path)
        return os.path.exists(path)

    def getmtime(self, path):
        path = self.normalize(path)

        try:
            return os.path.getmtime(path)
        except OSError:
            return 0

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
    def get(self, path):
        path = self.normalize(path)
        fh = None
        try:
            fh = open(path, "rb")
            return fh.read()
        finally:
            if fh:
                fh.close()

    def put(self, path, content):
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

###############################
# Helper functions.
###############################


def _join(base, path):
    path = path.replace("\\", "/").replace("//", "/")
    if base is None:
        return path
    return os.path.join(base, path.lstrip("/")).replace("\\", "/")


# TODO: Create an extension of the base class TransportFile

class TransportFileLocal(TransportFile):
    def __init__(self, file, chunk_size = 1024):
        super().__init__(file)
        self.chunk_size = chunk_size
        self.iterator = iter(partial(self.file.read, self.chunk_size), b'')

    def iterator(self):
        return self.iterator

    def read(self):
        return self.file.read(self.chunk_size)