import logging
import os
import posixpath
import requests

from assemblyline.common.exceptions import ChainAll
from assemblyline.filestore.transport.base import Transport, TransportException, normalize_srl_path


@ChainAll(TransportException)
class TransportHTTP(Transport):
    """
    HTTP Transport class.
    """
    def __init__(self, scheme='http', base=None, host=None, password=None, user=None, pki=None, port=None, verify=None):
        self.log = logging.getLogger('assemblyline.transport.http')
        self.base = base
        self.host = host
        self.password = password
        self.user = user
        self.pki = pki
        self.scheme = scheme
        self.verify = verify

        if not port:
            if scheme == 'http':
                port = 80
            else:
                port = 443
        self.port = port

        if user and password:
            self.auth = (user, password)
        else:
            self.auth = None

        def http_normalize(path):
            if '/' in path or len(path) != 64:
                s = posixpath.join(self.base, path)
            else:
                s = posixpath.join(self.base, normalize_srl_path(path))

            return "{scheme}://{host}:{port}{path}".format(scheme=scheme, host=host, port=port, path=s)

        self._session = None

        super(TransportHTTP, self).__init__(normalize=http_normalize)

    @property
    def session(self):
        if self._session is None:
            self._session = requests.Session()
        return self._session

    def __str__(self):
        out = "%s://" % self.scheme
        if self.user:
            out += "%s@" % self.user
        out += "%s:%s" % (self.host, self.port)
        if self.base:
            out += self.base
        return out
        
    def close(self):
        if self._session:
            self._session.close()

    def delete(self, path):
        raise TransportException("READ ONLY TRANSPORT: Method not implemented")

    def exists(self, path):
        path = self.normalize(path)
        resp = self.session.head(path, auth=self.auth, cert=self.pki, verify=self.verify)
        return resp.ok

    def makedirs(self, path):
        raise TransportException("READ ONLY TRANSPORT: Method not implemented")

    # File based functions
    def download(self, src_path, dst_path):
        dir_path = os.path.dirname(dst_path)
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)
        with open(dst_path, 'wb') as localfile:
            src_path = self.normalize(src_path)
            resp = self.session.get(src_path, auth=self.auth, cert=self.pki, verify=self.verify)
            if resp.ok:
                for chunk in resp.iter_content(chunk_size=1024):
                    if chunk:
                        localfile.write(chunk)
            else:
                raise TransportException("[%s] %s: %s" % (resp.status_code, resp.reason, src_path))

    def upload(self, src_path, dst_path):
        raise TransportException("READ ONLY TRANSPORT: Method not implemented")

    def upload_batch(self, local_remote_tuples):
        raise TransportException("READ ONLY TRANSPORT: Method not implemented")

    # Buffer based functions
    def get(self, path: str) -> bytes:
        path = self.normalize(path)
        resp = self.session.get(path, auth=self.auth, cert=self.pki, verify=self.verify)
        if resp.ok:
            return resp.content
        else:
            raise TransportException("[%s] %s: %s" % (resp.status_code, resp.reason, path))

    def put(self, dst_path, content):
        raise TransportException("READ ONLY TRANSPORT: Method not implemented")
