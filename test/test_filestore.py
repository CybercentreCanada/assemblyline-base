import os
import tempfile
import threading
import traceback

import pytest
from assemblyline.filestore.transport.base import TransportException

from assemblyline.filestore import FileStore, create_transport

_temp_body_a = b'temporary file string'


def _temp_ftp_server(start: threading.Event, stop: threading.Event):
    try:
        from pyftpdlib.authorizers import DummyAuthorizer
        from pyftpdlib.handlers import FTPHandler
        from pyftpdlib.servers import FTPServer

        with tempfile.TemporaryDirectory() as temp_dir:
            authorizer = DummyAuthorizer()
            authorizer.add_user("user", "12345", temp_dir, perm="elradfmwMT")
            authorizer.add_anonymous(temp_dir)

            handler = FTPHandler
            handler.authorizer = authorizer
            server = FTPServer(("127.0.0.1", 21111), handler)
            while not stop.is_set():
                start.set()
                server.serve_forever(timeout=1, blocking=False)
    except Exception:
        traceback.print_exc()


@pytest.fixture
def temp_ftp_server():
    start = threading.Event()
    stop = threading.Event()
    thread = threading.Thread(target=_temp_ftp_server, args=[start, stop])
    try:
        thread.start()
        start.wait(5)
        yield
    finally:
        stop.set()
        thread.join()


def test_azure():
    """
    Azure filestore by downloading a file from our public storage blob
    """
    fs = FileStore("azure://alpytest.blob.core.windows.net/pytest/", connection_attempts=2)
    assert fs.exists('test') != []
    assert fs.get('test') is not None
    with pytest.raises(TransportException):
        fs.put('bob', 'bob')


def test_http():
    """
    Test HTTP FileStore by fetching the assemblyline page on
    CSE's cyber center page.
    """
    tp = create_transport('http://github.com/CybercentreCanada/')
    assert tp.base == '/CybercentreCanada/'
    assert tp.host == 'github.com'
    assert tp.scheme == 'http'

    fs = FileStore('http://github.com/CybercentreCanada/')
    assert fs.exists('assemblyline-base') != []
    assert fs.get('assemblyline-base') is not None


def test_https():
    """
    Test HTTPS FileStore by fetching the assemblyline page on
    CSE's cyber center page.
    """
    fs = FileStore('https://github.com/CybercentreCanada/')
    assert fs.exists('assemblyline-base') != []
    assert fs.get('assemblyline-base') is not None


# def test_sftp():
#     """
#     Test SFTP FileStore by fetching the readme.txt file from
#     Rebex test server.
#     """
#     fs = FileStore('sftp://demo:password@test.rebex.net')
#     assert fs.exists('readme.txt') != []
#     assert fs.get('readme.txt') is not None


def test_ftp(temp_ftp_server):
    """
    Test FTP FileStore by fetching the readme.txt file from
    Rebex test server.
    """
    fs = FileStore('ftp://user:12345@localhost:21111')
    common_actions(fs)

# def test_ftps():
#     """
#     Test FTP over TLS FileStore by fetching the readme.txt file from
#     Rebex test server.
#     """
#     fs = FileStore('ftps://demo:password@test.rebex.net')
#     assert fs.exists('readme.txt') != []
#     assert fs.get('readme.txt') is not None


def test_file():
    """
    Test Local FileStore by fetching the README.md file from
    the assemblyline core repo directory.

    Note: This test will fail if pytest is not ran from the root
          of the assemblyline core repo.
    """
    fs = FileStore('file://%s' % os.path.dirname(__file__))
    assert fs.exists(os.path.basename(__file__)) != []
    assert fs.get(os.path.basename(__file__)) is not None

    with tempfile.TemporaryDirectory() as temp_dir:
        fs = FileStore('file://' + temp_dir)
        common_actions(fs)


def test_s3():
    """
    Test Amazon S3 FileStore by fetching a test file from
    the assemblyline-support bucket on Amazon S3.
    """
    fs = FileStore('s3://AKIAIIESFCKMSXUP6KWQ:Uud08qLQ48Cbo9RB7b+H+M97aA2wdR8OXaHXIKwL@'
                   's3.amazonaws.com/?s3_bucket=assemblyline-support&aws_region=us-east-1')
    assert fs.exists('al4_s3_pytest.txt') != []
    assert fs.get('al4_s3_pytest.txt') is not None


def test_minio():
    """
    Test Minio FileStore by pushing and fetching back content from it.
    """
    content = b"THIS IS A MINIO TEST"

    fs = FileStore('s3://al_storage_key:Ch@ngeTh!sPa33w0rd@localhost:9000/?s3_bucket=test&use_ssl=False')
    assert fs.delete('al4_minio_pytest.txt') is None
    assert fs.put('al4_minio_pytest.txt', content) != []
    assert fs.exists('al4_minio_pytest.txt') != []
    assert fs.get('al4_minio_pytest.txt') == content
    assert fs.delete('al4_minio_pytest.txt') is None


def common_actions(fs):
    # Write and read file body directly
    fs.put('put', _temp_body_a)
    assert fs.get('put') == _temp_body_a

    # Write a file body by batch upload
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_file_a = os.path.join(temp_dir, 'a')
        with open(temp_file_a, 'wb') as handle:
            handle.write(_temp_body_a)
        temp_file_b = os.path.join(temp_dir, 'a')
        with open(temp_file_b, 'wb') as handle:
            handle.write(_temp_body_a)

        failures = fs.upload_batch([
            (temp_file_a, 'upload/a'),
            (temp_file_b, 'upload/b')
        ])
        assert len(failures) == 0, failures
        assert fs.exists('upload/a')
        assert fs.exists('upload/b')

        # Read a file body by download
        temp_file_name = os.path.join(temp_dir, 'scratch')
        fs.download('upload/b', temp_file_name)
        assert open(temp_file_name, 'rb').read() == _temp_body_a

    assert fs.exists('put')
    fs.delete('put')
    assert not fs.exists('put')
