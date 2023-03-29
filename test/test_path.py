from assemblyline.common import path


def test_strip_path_injection_linux():
    test_str = 'filename'
    assert path.strip_path_inclusion_linux(test_str) == 'filename'

    test_str = 'foldername/filename'
    assert path.strip_path_inclusion_linux(test_str) == 'foldername/filename'

    test_str = '.filename'
    assert path.strip_path_inclusion_linux(test_str) == '.filename'

    test_str = '.foldername/filename'
    assert path.strip_path_inclusion_linux(test_str) == '.foldername/filename'

    test_str = './foldername/filename'
    assert path.strip_path_inclusion_linux(test_str) == 'foldername/filename'

    test_str = '/foldername/filename'
    assert path.strip_path_inclusion_linux(test_str) == 'foldername/filename'

    test_str = '../foldername/filename'
    assert path.strip_path_inclusion_linux(test_str) == 'foldername/filename'

    test_str = '../../../../foldername/filename'
    assert path.strip_path_inclusion_linux(test_str) == 'foldername/filename'

    test_str = '.././//./..//../../../foldername/filename'
    assert path.strip_path_inclusion_linux(test_str) == 'foldername/filename'

    test_str = '////./..//../../../foldername/filename'
    assert path.strip_path_inclusion_linux(test_str) == 'foldername/filename'

    test_str = 'realfolder/../../../foldername/filename'
    assert path.strip_path_inclusion_linux(test_str) == 'realfolder/foldername/filename'

    test_str = '..foldername/..filename'
    assert path.strip_path_inclusion_linux(test_str) == '..foldername/..filename'

    test_str = '.././//./..//../../../foldername/../../././//../filename'
    assert path.strip_path_inclusion_linux(test_str) == 'foldername/filename'


def test_strip_path_injection_windows():
    test_str = 'filename'
    assert path.strip_path_inclusion_windows(test_str) == 'filename'

    test_str = 'foldername\\filename'
    assert path.strip_path_inclusion_windows(test_str) == 'foldername\\filename'

    test_str = '.filename'
    assert path.strip_path_inclusion_windows(test_str) == '.filename'

    test_str = '.foldername\\filename'
    assert path.strip_path_inclusion_windows(test_str) == '.foldername\\filename'

    test_str = '.\\foldername\\filename'
    assert path.strip_path_inclusion_windows(test_str) == 'foldername\\filename'

    test_str = 'Z:\\foldername\\filename'
    assert path.strip_path_inclusion_windows(test_str) == 'foldername\\filename'

    test_str = '..\\foldername\\filename'
    assert path.strip_path_inclusion_windows(test_str) == 'foldername\\filename'

    test_str = '..\\..\\..\\..\\foldername\\filename'
    assert path.strip_path_inclusion_windows(test_str) == 'foldername\\filename'

    test_str = '..\\.\\\\\\.\\..\\..\\..\\..\\foldername\\filename'
    assert path.strip_path_inclusion_windows(test_str) == 'foldername\\filename'

    test_str = 'realfolder\\..\\..\\..\\..\\..\\..\\foldername\\filename'
    assert path.strip_path_inclusion_windows(test_str) == 'realfolder\\foldername\\filename'

    test_str = 'realfolder\\..\\..\\realfolder2\\..\\..\\..\\foldername\\filename'
    assert path.strip_path_inclusion_windows(test_str) == 'realfolder\\realfolder2\\foldername\\filename'

    test_str = 'C:\\foldername\\filename'
    assert path.strip_path_inclusion_windows(test_str) == 'foldername\\filename'
