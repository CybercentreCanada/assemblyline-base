import os
import tempfile
import threading
import traceback

import pytest
from assemblyline.filestore import FileStore
from assemblyline.filestore.transport.base import TransportException

_temp_body_a = b'temporary file string'


def _temp_ftp_server(start: threading.Event, stop: threading.Event, user, password, port, secure):
    try:
        from pyftpdlib.authorizers import DummyAuthorizer
        from pyftpdlib.handlers import FTPHandler, TLS_FTPHandler
        from pyftpdlib.servers import FTPServer

        with tempfile.TemporaryDirectory() as temp_dir:
            authorizer = DummyAuthorizer()
            authorizer.add_user(user, password, temp_dir, perm="elradfmwMT")
            authorizer.add_anonymous(temp_dir)

            if secure:
                handler = TLS_FTPHandler
                handler.certfile = os.path.join(os.path.dirname(__file__), 'key.pem')
            else:
                handler = FTPHandler

            handler.authorizer = authorizer
            server = FTPServer(("127.0.0.1", port), handler)
            while not stop.is_set():
                start.set()
                server.serve_forever(timeout=1, blocking=False)
    except Exception:
        traceback.print_exc()


@pytest.fixture
def temp_ftp_server():
    start = threading.Event()
    stop = threading.Event()
    thread = threading.Thread(target=_temp_ftp_server, args=[start, stop, "user", "12345", 21111, False])
    try:
        thread.start()
        start.wait(5)
        yield 'user:12345@localhost:21111'
    finally:
        stop.set()
        thread.join()


@pytest.fixture
def temp_ftps_server():
    start = threading.Event()
    stop = threading.Event()
    thread = threading.Thread(target=_temp_ftp_server, args=[start, stop, "user", "12345", 21112, True])
    try:
        thread.start()
        start.wait(5)
        yield 'user:12345@localhost:21112'
    finally:
        stop.set()
        thread.join()


def test_azure():
    """
    Azure filestore by downloading a file from our public storage blob
    """
    fs = FileStore("azure://alpytest.blob.core.windows.net/pytest/", connection_attempts=2)
    assert fs.get('__missing_file__') is None
    assert fs.exists('test') != []
    assert fs.get('test') is not None
    with pytest.raises(TransportException):
        fs.put('bob', 'bob')
    assert "test" in list(fs.transports[0].list())
    assert list(fs.transports[0].list('abc')) == []


def test_http():
    """
    Test HTTP FileStore by fetching the assemblyline page on
    CSE's cyber center page.
    """
    fs = FileStore('http://github.com/CybercentreCanada/')
    assert 'github.com' in str(fs)
    httpx_tests(fs)


def test_https():
    """
    Test HTTPS FileStore by fetching the assemblyline page on
    CSE's cyber center page.
    """
    fs = FileStore('https://github.com/CybercentreCanada/')
    assert 'github.com' in str(fs)
    httpx_tests(fs)


def httpx_tests(fs):
    assert fs.get('__missing_file__') is None
    assert fs.exists('assemblyline-base') != []
    assert fs.get('assemblyline-base') is not None
    with tempfile.TemporaryDirectory() as temp_dir:
        local_base = os.path.join(temp_dir, 'base')
        fs.download('assemblyline-base', local_base)
        assert os.path.exists(local_base)


def test_sftp():
    """
    Test SFTP FileStore by fetching the readme.txt file from
    Rebex test server.
    """
    fs = FileStore('sftp://user:password@localhost:2222')
    common_actions(fs, check_listing=False)


def test_ftp(temp_ftp_server):
    """
    Run some operations against an in-process ftp server
    """
    with FileStore(f'ftp://{temp_ftp_server}') as fs:
        assert 'localhost' in str(fs)
        common_actions(fs)


def test_ftps(temp_ftps_server):
    """
    Run some operations against an in-process ftp server
    """
    with FileStore(f'ftps://{temp_ftps_server}') as fs:
        assert 'localhost' in str(fs)
        common_actions(fs)


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
        with FileStore('file://' + temp_dir) as fs:
            common_actions(fs)


def test_s3():
    """
    Test S3 FileStore using Minio by pushing and fetching back content from it.
    """
    content = b"THIS IS A MINIO TEST"

    fs = FileStore('s3://al_storage_key:Ch@ngeTh!sPa33w0rd@localhost:9000/?s3_bucket=test&use_ssl=False')
    assert fs.delete('al4_minio_pytest.txt') is None
    assert fs.put('al4_minio_pytest.txt', content) != []
    assert fs.exists('al4_minio_pytest.txt') != []
    assert fs.get('al4_minio_pytest.txt') == content
    assert fs.delete('al4_minio_pytest.txt') is None
    common_actions(fs)

def test_s3_aws():
    """
    Test S3 FileStore using simulated AWS S3 by pushing and fetching back content from it.
    """
    from base64 import b64encode

    from boto3.session import Session

    content = b"THIS IS AN AWS S3 TEST"

    # Setup the IAM role policy for the S3 bucket in emulated AWS environment (e.g., floci)
    os.environ['AWS_ENDPOINT_URL'] = 'http://localhost:4566'
    s = Session()
    iam_client = s.client('iam', aws_access_key_id="test", aws_secret_access_key="test", use_ssl=False)
    try:
        iam_client.create_role(RoleName="MockedIRSARole", AssumeRolePolicyDocument='{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Federated": "arn:aws:iam::000000000000:oidc-provider/localhost:4566"}, "Action": "sts:AssumeRoleWithWebIdentity"}]}')
    except iam_client.exceptions.EntityAlreadyExistsException:
        pass  # Role already exists, which is fine for our test setup
    iam_client.put_role_policy(RoleName="MockedIRSARole", PolicyName="S3Access", PolicyDocument='{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:CreateBucket", "s3:DeleteObject", "s3:GetObject", "s3:PutObject", "s3:ListBucket"], "Resource": ["arn:aws:s3:::al-storage", "arn:aws:s3:::al-storage/*"]}]}')

    # Create a web identity token to cover IRSA authentication flow
    with tempfile.NamedTemporaryFile(delete=False) as token_file:
        header = '{"alg": "HS256", "typ": "JWT"}'
        payload = '{"iss":"http://localhost:4566","sub":"system:serviceaccount:default:assemblyline","aud":["://amazonaws.com"],"exp":2082758400}'
        token = b64encode(header.encode()) + b'.' + b64encode(payload.encode()) + b'.test_signature'
        token_file.write(token)
        token_file_path = token_file.name

    # Set environment variables to simulate IRSA authentication for the AWS S3 FileStore
    os.environ['AWS_ROLE_ARN'] = 'arn:aws:iam::000000000000:role/MockedIRSARole'
    os.environ['AWS_WEB_IDENTITY_TOKEN_FILE'] = token_file_path

    fs = FileStore('s3://localhost:4566/?use_ssl=False')

    # Based on the policy, our client should have the necessary permissions to perform the following operations similar to the Minio test, but now against the AWS S3 emulation:
    assert fs.put('al4_aws_s3_pytest.txt', content) != []
    assert fs.exists('al4_aws_s3_pytest.txt') != []
    assert fs.get('al4_aws_s3_pytest.txt') == content
    assert fs.delete('al4_aws_s3_pytest.txt') is None
    common_actions(fs)

    # Cleanup the environment variables and temporary token file to ensure they don't interfere with other tests
    del os.environ['AWS_ENDPOINT_URL']
    del os.environ['AWS_ROLE_ARN']
    del os.environ['AWS_WEB_IDENTITY_TOKEN_FILE']
    os.remove(token_file_path)



def common_actions(fs, check_listing=True):
    # Make sure a missing file returns None
    assert fs.get('__missing_file__') is None

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

    fs.put('0' * 64, 'hello')
    fs.put('0' + '1' * 63, 'hello')
    fs.put('01' + '2' * 62, 'hello')
    fs.put('012' + '3' * 61, 'hello')
    fs.put('0123' + '4' * 60, 'hello')
    fs.put('01-file', 'hello')
    fs.put('012-file', 'hello')
    fs.put('0123-file', 'hello')
    fs.put('01234-file', 'hello')

    if check_listing:
        assert len(set(fs.transports[0].list('0'))) == 9
        assert len(set(fs.transports[0].list('01'))) == 8
        assert len(set(fs.transports[0].list('012'))) == 6
        assert len(set(fs.transports[0].list('0123'))) == 4
        assert set(fs.transports[0].list('01234')) == {'01234-file', '0123' + '4' * 60}
