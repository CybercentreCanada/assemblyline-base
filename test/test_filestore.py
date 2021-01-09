import os

import pytest
from assemblyline.filestore.transport.base import TransportException

from assemblyline.filestore import FileStore


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


# def test_ftp():
#     """
#     Test FTP FileStore by fetching the readme.txt file from
#     Rebex test server.
#     """
#     fs = FileStore('ftp://demo:password@test.rebex.net')
#     assert fs.exists('readme.txt') != []
#     assert fs.get('readme.txt') is not None


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

