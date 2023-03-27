from assemblyline.common import path


def test_strip_leading_injection():
    test_str = 'filename'
    assert path.strip_leading_inclusion_linux(test_str) == 'filename'

    test_str = 'foldername/filename'
    assert path.strip_leading_inclusion_linux(test_str) == 'foldername/filename'

    test_str = '.filename'
    assert path.strip_leading_inclusion_linux(test_str) == '.filename'

    test_str = '.foldername/filename'
    assert path.strip_leading_inclusion_linux(test_str) == '.foldername/filename'

    test_str = './foldername/filename'
    assert path.strip_leading_inclusion_linux(test_str) == 'foldername/filename'

    test_str = '/foldername/filename'
    assert path.strip_leading_inclusion_linux(test_str) == 'foldername/filename'

    test_str = '../foldername/filename'
    assert path.strip_leading_inclusion_linux(test_str) == 'foldername/filename'

    test_str = '../../../../foldername/filename'
    assert path.strip_leading_inclusion_linux(test_str) == 'foldername/filename'

    test_str = '.././//./..//../../../foldername/filename'
    assert path.strip_leading_inclusion_linux(test_str) == 'foldername/filename'
