import logging
import os
import posixpath
import pysftp
import uuid
import warnings

from io import BytesIO

from paramiko import SSHException

from assemblyline.common.exceptions import ChainAll
from assemblyline.filestore.transport.base import Transport, TransportException, normalize_srl_path


def reconnect_retry_on_fail(func):
    def new_func(self, *args, **kwargs):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")

            if not self.validate_host:
                cnopts = pysftp.CnOpts()
                cnopts.hostkeys = None
            else:
                cnopts = None

            try:
                if not self.sftp:
                    self.sftp = pysftp.Connection(self.host,
                                                  username=self.user,
                                                  password=self.password,
                                                  private_key=self.private_key,
                                                  private_key_pass=self.private_key_pass,
                                                  cnopts=cnopts)
                return func(self, *args, **kwargs)
            except SSHException:
                pass

            # The previous attempt at calling original func failed.
            # Reset the connection and try again (one time).
            if self.sftp:
                self.sftp.close()   # Just best effort.

            # The original func will reconnect automatically.
            self.sftp = pysftp.Connection(self.host,
                                          username=self.user,
                                          password=self.password,
                                          private_key=self.private_key,
                                          private_key_pass=self.private_key_pass,
                                          cnopts=cnopts)
            return func(self, *args, **kwargs)

    new_func.__name__ = func.__name__
    new_func.__doc__ = func.__doc__
    return new_func


@ChainAll(TransportException)
class TransportSFTP(Transport):
    """
    SFTP Transport class.
    """
    def __init__(self, base=None, host=None, password=None, user=None, private_key=None, private_key_pass=None,
                 validate_host=False):
        self.log = logging.getLogger('assemblyline.transport.sftp')
        self.base = base
        self.sftp = None
        self.host = host
        self.password = password
        self.user = user
        self.private_key = private_key
        self.private_key_pass = private_key_pass
        self.validate_host = validate_host

        def sftp_normalize(path):
            # If they've provided an absolute path. Leave it a is.
            if path.startswith('/'):
                s = path
            # Relative paths 
            elif '/' in path or len(path) != 64:
                s = posixpath.join(self.base, path)
            else:
                s = posixpath.join(self.base, normalize_srl_path(path))  
            self.log.debug('sftp normalized: %s -> %s', path, s)
            return s

        super(TransportSFTP, self).__init__(normalize=sftp_normalize)

    def __str__(self):
        return 'sftp://{}@{}{}'.format(self.user, self.host, self.base)
        
    def close(self):
        if self.sftp:
            self.sftp.close()

    @reconnect_retry_on_fail
    def delete(self, path):
        path = self.normalize(path)
        self.sftp.remove(path)

    @reconnect_retry_on_fail
    def download(self, src_path, dst_path):
        dir_path = os.path.dirname(dst_path)

        if not os.path.exists(dir_path):
            os.makedirs(dir_path)

        src_path = self.normalize(src_path)
        self.sftp.get(src_path, dst_path)
        
    @reconnect_retry_on_fail
    def exists(self, path):
        path = self.normalize(path)
        return self.sftp.exists(path)
        
    @reconnect_retry_on_fail
    def get(self, path):
        path = self.normalize(path)
        bio = BytesIO()
        with self.sftp.open(path) as sftp_handle:
            bio.write(sftp_handle.read())
        return bio.getvalue()
    
    @reconnect_retry_on_fail
    def makedirs(self, path):
        path = self.normalize(path)
        self.sftp.makedirs(path)

    @reconnect_retry_on_fail
    def put(self, src_path, dst_path):
        dst_path = self.normalize(dst_path)
        dirname = posixpath.dirname(dst_path)
        filename = posixpath.basename(dst_path)
        tempname = str(uuid.uuid4())
        temppath = posixpath.join(dirname, tempname)
        finalpath = posixpath.join(dirname, filename)
        assert(finalpath == dst_path)
        self.makedirs(dirname)
        self.sftp.put(src_path, temppath)
        self.sftp.rename(temppath, finalpath)
        assert(self.exists(dst_path))

    @reconnect_retry_on_fail
    def put_batch(self, local_remote_tuples):
        return super(TransportSFTP, self).put_batch(local_remote_tuples)
