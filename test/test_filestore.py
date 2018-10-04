from assemblyline.filestore import FileStore


def test_http():
    """

    :return:
    """
    fs = FileStore('http://cyber.gc.ca/en/')
    assert fs.exists('assemblyline') != []
    assert fs.get('assemblyline') is not None


def test_https():
    """

    :return:
    """
    fs = FileStore('https://cyber.gc.ca/en/')
    assert fs.exists('assemblyline') != []
    assert fs.get('assemblyline') is not None


def test_sftp():
    """

    :return:
    """
    fs = FileStore('sftp://demo:password@test.rebex.net')
    assert fs.exists('readme.txt') != []
    assert fs.get('readme.txt') is not None


def test_ftp():
    """

    :return:
    """
    fs = FileStore('ftp://demo:password@test.rebex.net')
    assert fs.exists('readme.txt') != []
    assert fs.get('readme.txt') is not None


def test_ftps():
    """

    :return:
    """
    fs = FileStore('ftps://demo:password@test.rebex.net')
    assert fs.exists('readme.txt') != []
    assert fs.get('readme.txt') is not None


def test_file():
    """

    :return:
    """
    fs = FileStore('file://./')
    assert fs.exists('README.md') != []
    assert fs.get('README.md') is not None


def test_s3():
    """

    :return:
    """
    fs = FileStore('s3://AKIAIIESFCKMSXUP6KWQ:Uud08qLQ48Cbo9RB7b+H+M97aA2wdR8OXaHXIKwL@'
                   's3.amazonaws.com/?s3_bucket=assemblyline-support&aws_region=us-east-1')
    assert fs.exists('al4_s3_pytest.txt') != []
    assert fs.get('al4_s3_pytest.txt') is not None
