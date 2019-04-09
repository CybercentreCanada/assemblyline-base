import baseconv
import ftplib
import logging
import os
import posixpath
import time
import uuid
import errno

from io import BytesIO

from assemblyline.common.exceptions import ChainAll
from assemblyline.common.path import splitpath
from assemblyline.filestore.transport.base import Transport, TransportException, normalize_srl_path


def reconnect_retry_on_fail(func):
    def new_func(self, *args, **kwargs):
        max_retry = 3
        try_count = 0

        while try_count < max_retry:
            try:
                if not self.ftp:
                    if self.use_tls:
                        self.ftp = ftplib.FTP_TLS()
                        self.ftp.connect(self.host, port=self.port)
                        self.ftp.auth()
                        self.ftp.prot_p()

                    else:
                        self.ftp = ftplib.FTP()
                        self.ftp.connect(self.host, port=self.port)

                    self.ftp.login(self.user, self.password)
                    self.ftp.sendcmd("TYPE I")
                    try:
                        self.ftp.voidcmd('site umask 002')
                    except ftplib.Error:
                        pass

                return func(self, *args, **kwargs)
            except ftplib.error_perm as e:
                if str(e).startswith('550'):
                    raise
                msg = str(e) or "Unknown permission error"

            except ftplib.error_temp as e:
                msg = str(e) or "Unknown temporary error"

            except ftplib.error_reply as e:
                msg = str(e) or "Unknown reply error"

            except ftplib.Error as e:
                msg = str(e) or "Unknown FTP Error"

            except IOError as e:
                # May need to ignore other errors as well
                if e.errno not in (errno.EPIPE, errno.ECONNRESET):
                    raise
                msg = "IOError #%s" % e.errno

            # Prevent any stale connection errors to show up in the warnings
            # as these error can happen often if the ftp connection is not used
            # enough.
            if msg.startswith('421') or msg.startswith('425') or msg == "IOError #32" or msg == "IOError #104":
                self.log.info("FTP [%s]: %s" % (self.host, msg))
            else:
                self.log.warning("FTP [%s]: %s" % (self.host, msg))

            # The previous attempt at calling original func failed.
            # Reset the connection and try again.
            try:
                if self.ftp:
                    self.ftp.close()  # Just best effort.
            except ftplib.Error:
                pass

            time.sleep((2 ** try_count) / (2.00 ** (max_retry * 2)))

            self.ftp = None
            try_count += 1

        raise TransportException("Max retries reach for function: %s(%s)" % (func.__name__, ", ".join(map(repr, args))))

    new_func.__name__ = func.__name__
    new_func.__doc__ = func.__doc__
    return new_func


@ChainAll(TransportException)
class TransportFTP(Transport):
    """
    FTP Transport class.
    """
    def __init__(self, base=None, host=None, password=None, user=None, port=None, use_tls=None):
        self.log = logging.getLogger('assemblyline.transport.ftp')
        self.base = base
        self.ftp = None
        self.host = host
        self.port = int(port or 21)
        self.password = password
        self.user = user
        self.use_tls = use_tls

        def ftp_normalize(path):
            # If they've provided an absolute path. Leave it a is.
            if path.startswith('/'):
                s = path
            # Relative paths
            elif '/' in path or len(path) != 64:
                s = posixpath.join(self.base, path)
            else:
                s = posixpath.join(self.base, normalize_srl_path(path))
            self.log.debug('ftp normalized: %s -> %s', path, s)
            return s

        super(TransportFTP, self).__init__(normalize=ftp_normalize)

    def __str__(self):
        out = 'ftp://{}@{}'.format(self.user, self.host)
        if self.base:
            out += self.base
        return out

    def close(self):
        if self.ftp:
            self.ftp.close()

    @reconnect_retry_on_fail
    def delete(self, path):
        path = self.normalize(path)
        self.ftp.delete(path)

    @reconnect_retry_on_fail
    def exists(self, path):
        path = self.normalize(path)
        self.log.debug('Checking for existence of %s', path)
        size = None
        try:
            size = self.ftp.size(path)
        except ftplib.error_perm as e:
            # If the file doesnt exist we get a 550.
            if not str(e).startswith('550'):
                raise
        return size is not None

    @reconnect_retry_on_fail
    def makedirs(self, path):
        self.log.debug("making dirs: %s", path)
        subdirs = splitpath(path, '/')
        for i in range(len(subdirs)):
            try:
                d = posixpath.sep + posixpath.join(*subdirs[:i + 1])
                self.ftp.mkd(d)
            except ftplib.Error:
                pass

    # File based functions
    @reconnect_retry_on_fail
    def download(self, src_path, dst_path):
        dir_path = os.path.dirname(dst_path)
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)
        with open(dst_path, 'wb') as localfile:
            src_path = self.normalize(src_path)
            self.ftp.retrbinary('RETR ' + src_path, localfile.write)

    @reconnect_retry_on_fail
    def upload(self, src_path, dst_path):
        dst_path = self.normalize(dst_path)
        dirname = posixpath.dirname(dst_path)
        filename = posixpath.basename(dst_path)
        tempname = baseconv.base62.encode(uuid.uuid4().int)
        temppath = posixpath.join(dirname, tempname)
        finalpath = posixpath.join(dirname, filename)
        assert (finalpath == dst_path)
        self.makedirs(dirname)
        with open(src_path, 'rb') as localfile:
            self.log.debug("Storing: %s", temppath)
            self.ftp.storbinary('STOR ' + temppath, localfile)
        self.log.debug("Rename: %s -> %s", temppath, finalpath)
        self.ftp.rename(temppath, finalpath)
        assert (self.exists(dst_path))

    @reconnect_retry_on_fail
    def upload_batch(self, local_remote_tuples):
        return super(TransportFTP, self).upload_batch(local_remote_tuples)

    # Buffer based functions
    @reconnect_retry_on_fail
    def get(self, path):
        path = self.normalize(path)
        bio = BytesIO()
        self.ftp.retrbinary('RETR ' + path, bio.write)
        return bio.getvalue()

    @reconnect_retry_on_fail
    def put(self, dst_path, content):
        dst_path = self.normalize(dst_path)
        dirname = posixpath.dirname(dst_path)
        filename = posixpath.basename(dst_path)
        tempname = baseconv.base62.encode(uuid.uuid4().int)
        temppath = posixpath.join(dirname, tempname)
        finalpath = posixpath.join(dirname, filename)
        assert (finalpath == dst_path)
        self.makedirs(dirname)

        if isinstance(content, str):
            content = content.encode('utf-8')

        with BytesIO(content) as file_io:
            self.log.debug("Storing: %s", temppath)
            self.ftp.storbinary('STOR ' + temppath, file_io)

            self.log.debug("Rename: %s -> %s", temppath, finalpath)
            self.ftp.rename(temppath, finalpath)
            assert (self.exists(dst_path))

