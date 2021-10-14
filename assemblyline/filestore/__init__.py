from __future__ import annotations

import json
import logging
from typing import AnyStr, TYPE_CHECKING, Optional, Tuple
from urllib.parse import urlparse, parse_qs, unquote

import elasticapm

from assemblyline.common.exceptions import get_stacktrace_info
from assemblyline.filestore.transport.azure import TransportAzure
from assemblyline.filestore.transport.ftp import TransportFTP
from assemblyline.filestore.transport.http import TransportHTTP
from assemblyline.filestore.transport.local import TransportLocal
from assemblyline.filestore.transport.s3 import TransportS3
from assemblyline.filestore.transport.sftp import TransportSFTP

if TYPE_CHECKING:
    from assemblyline.filestore.transport.base import Transport


class FileStoreException(Exception):
    pass


class CorruptedFileStoreException(Exception):
    pass


def _get_extras(parsed_dict, valid_str_keys=None, valid_bool_keys=None):
    if not valid_str_keys:
        valid_str_keys = []
    if not valid_bool_keys:
        valid_bool_keys = []

    out = {}
    for k, v in parsed_dict.items():
        if k in valid_bool_keys:
            if v[0].lower() == 'true':
                out[k] = True
            elif v[0].lower() != 'true':
                out[k] = False
        if k in valid_str_keys:
            out[k] = v[0]

    return out


def create_transport(url, connection_attempts=None):
    """
    Transport are being initiated using an URL. They follow the normal url format:
    scheme://user:pass@host:port/path/to/file

    In this example, it will extract the following parameters:
    scheme: scheme
    host: host
    user: user
    password: pass
    port: port
    base: /path/to/file

    Certain transports can have extra parameters, those parameters need to be specified in the query part of the url.
    e.g.: sftp://host.com/path/to/file?private_key=/etc/ssl/pkey&private_key_pass=pass&validate_host=true
    scheme: sftp
    host: host.com
    user:
    password:
    private_key: /etc/ssl/pkey
    private_key_pass: pass
    validate_host: True

    NOTE: For transport with extra parameters, only specific extra parameters are allow. This is the list of extra
          parameter allowed:

          ftp: use_tls (bool)
          http: pki (string)
          sftp: private_key (string), private_key_pass (string), validate_host (bool)
          s3: aws_region (string), s3_bucket(string), use_ssl (bool), verify (bool)
          file: normalize (bool)

    """

    parsed = urlparse(url)

    base = parsed.path or '/'
    host = parsed.hostname
    if host == ".":
        base = "%s%s" % (host, base)
    port = parsed.port
    if parsed.password:
        password = unquote(parsed.password)
    else:
        password = ''
    user = parsed.username or ''

    scheme = parsed.scheme.lower()
    if scheme == 'ftp' or scheme == 'ftps':
        valid_bool_keys = ['use_tls']
        extras = _get_extras(parse_qs(parsed.query), valid_bool_keys=valid_bool_keys)
        if scheme == 'ftps':
            extras['use_tls'] = True

        t = TransportFTP(base=base, host=host, password=password, user=user, port=port, **extras)

    elif scheme == "sftp":
        valid_str_keys = ['private_key', 'private_key_pass']
        valid_bool_keys = ['validate_host']
        extras = _get_extras(parse_qs(parsed.query), valid_str_keys=valid_str_keys, valid_bool_keys=valid_bool_keys)

        t = TransportSFTP(base=base, host=host, password=password, user=user, **extras)

    elif scheme == 'http' or scheme == 'https':
        valid_str_keys = ['pki']
        valid_bool_keys = ['verify']
        extras = _get_extras(parse_qs(parsed.query), valid_str_keys=valid_str_keys, valid_bool_keys=valid_bool_keys)

        t = TransportHTTP(scheme=scheme, base=base, host=host, password=password, user=user, port=port, **extras)

    elif scheme == 'file':
        valid_bool_keys = ['normalize']
        extras = _get_extras(parse_qs(parsed.query), valid_bool_keys=valid_bool_keys)

        t = TransportLocal(base=base, **extras)

    elif scheme == 's3':
        valid_str_keys = ['aws_region', 's3_bucket']
        valid_bool_keys = ['use_ssl', 'verify']
        extras = _get_extras(parse_qs(parsed.query), valid_str_keys=valid_str_keys, valid_bool_keys=valid_bool_keys)

        t = TransportS3(base=base, host=host, port=port, accesskey=user, secretkey=password,
                        connection_attempts=connection_attempts, **extras)

    elif scheme == 'azure':
        valid_str_keys = ['access_key']
        extras = _get_extras(parse_qs(parsed.query), valid_str_keys=valid_str_keys)

        t = TransportAzure(base=base, host=host, connection_attempts=connection_attempts, **extras)

    else:
        raise FileStoreException("Unknown transport: %s" % scheme)

    return t


class FileStore(object):
    def __init__(self, *transport_urls, connection_attempts=None):
        self.log = logging.getLogger('assemblyline.transport')
        self.transports = [create_transport(url, connection_attempts) for url in transport_urls]
        self.local_transports = [
            t for t in self.transports if isinstance(t, TransportLocal)
        ]

    def __enter__(self):
        return self

    def __exit__(self, ex_type, exc_val, exc_tb):
        self.close()

    def __str__(self):
        return ', '.join(str(t) for t in self.transports)

    def close(self):
        for t in self.transports:
            try:
                t.close()
            except Exception as ex:
                trace = get_stacktrace_info(ex)
                self.log.warning('Transport problem: %s', trace)

    @elasticapm.capture_span(span_type='filestore')
    def delete(self, path: str, location='all'):
        with elasticapm.capture_span(name='delete', span_type='filestore', labels={'path': path}):
            for t in self.slice(location):
                try:
                    t.delete(path)
                except Exception as ex:
                    trace = get_stacktrace_info(ex)
                    self.log.info('Transport problem: %s', trace)

    @elasticapm.capture_span(span_type='filestore')
    def download(self, src_path: str, dest_path: str, location='any'):
        successful = False
        transports = []
        download_errors = []
        for t in self.slice(location):
            try:
                t.download(src_path, dest_path)
                transports.append(t)
                successful = True
                break
            except Exception as ex:
                download_errors.append((str(t), str(ex)))

        if not successful:
            raise FileStoreException('No transport succeeded => %s' % json.dumps(download_errors))
        return transports

    @elasticapm.capture_span(span_type='filestore')
    def exists(self, path, location='any') -> list[Transport]:
        transports = []
        for t in self.slice(location):
            try:
                if t.exists(path):
                    transports.append(t)
                    if location == 'any':
                        break
            except Exception as ex:
                trace = get_stacktrace_info(ex)
                self.log.warning('Transport problem: %s', trace)
        return transports

    @elasticapm.capture_span(span_type='filestore')
    def get(self, path: str, location='any') -> Optional[bytes]:
        for t in self.slice(location):
            try:
                if t.exists(path):
                    return t.get(path)
            except Exception as ex:
                trace = get_stacktrace_info(ex)
                self.log.warning('Transport problem: %s', trace)
        return None

    @elasticapm.capture_span(span_type='filestore')
    def put(self, dst_path: str, content: AnyStr, location='all', force=False) -> list[Transport]:
        transports = []
        for t in self.slice(location):
            if force or not t.exists(dst_path):
                transports.append(t)
                t.put(dst_path, content)
                if not t.exists(dst_path):
                    raise FileStoreException('File transfer failed. Remote file does not '
                                             'exist for %s on %s (%s)' % (dst_path, location, t))
        return transports

    def slice(self, location):
        start, end = {
            'all': (0, len(self.transports)),
            'any': (0, len(self.transports)),
            'far': (-1, len(self.transports)),
            'near': (0, 1),
        }[location]

        transports = self.transports[start:end]
        assert(len(transports) >= 1)
        return transports

    @elasticapm.capture_span(span_type='filestore')
    def upload(self, src_path: str, dst_path: str, location='all', force=False) -> list[Transport]:
        transports = []
        for t in self.slice(location):
            if force or not t.exists(dst_path):
                transports.append(t)
                t.upload(src_path, dst_path)
                if not t.exists(dst_path):
                    raise FileStoreException('File transfer failed. Remote file does not '
                                             'exist for %s on %s (%s)' % (dst_path, location, t))
        return transports

    @elasticapm.capture_span(span_type='filestore')
    def upload_batch(self, local_remote_tuples, location='all') -> list[Tuple[str, str, str]]:
        failed_tuples = []
        for (src_path, dst_path) in local_remote_tuples:
            try:
                self.upload(src_path, dst_path, location)
            except Exception as ex:
                trace = get_stacktrace_info(ex)
                failed_tuples.append((src_path, dst_path, trace))
        return failed_tuples
