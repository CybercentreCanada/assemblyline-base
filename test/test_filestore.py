from assemblyline.filestore import FileStore


def test_http():
    """

    :return:
    """
    fs = FileStore('http://google.ca')
    assert fs.exists('index.html') != []
    assert fs.get('index.html') is not None


def test_https():
    """

    :return:
    """
    fs = FileStore('https://google.ca')
    assert fs.exists('index.html') != []
    assert fs.get('index.html') is not None


def test_sftp():
    """

    :return:
    """
    pass


def test_ftp():
    """

    :return:
    """
    pass


def test_ftps():
    """

    :return:
    """
    pass


def test_file():
    """

    :return:
    """
    pass


def test_s3():
    """

    :return:
    """
    pass
