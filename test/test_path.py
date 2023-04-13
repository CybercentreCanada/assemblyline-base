from assemblyline.common import path


def test_strip_path_injection_linux():
    test_str = 'filename'
    assert path.strip_path_inclusion(test_str, "/home/al-user") == 'filename'

    test_str = 'foldername/filename'
    assert path.strip_path_inclusion(test_str, "/home/al-user") == 'foldername/filename'

    test_str = '.filename'
    assert path.strip_path_inclusion(test_str, "/home/al-user") == '.filename'

    test_str = '.foldername/filename'
    assert path.strip_path_inclusion(test_str, "/home/al-user") == '.foldername/filename'

    test_str = './foldername/filename'
    assert path.strip_path_inclusion(test_str, "/home/al-user") == './foldername/filename'

    test_str = '/foldername/filename'
    assert path.strip_path_inclusion(test_str, "/home/al-user") == 'filename'

    test_str = '../foldername/filename'
    assert path.strip_path_inclusion(test_str, "/home/al-user") == 'filename'

    test_str = '../../../../foldername/filename'
    assert path.strip_path_inclusion(test_str, "/home/al-user") == 'filename'

    test_str = '.././//./..//../../../foldername/filename'
    assert path.strip_path_inclusion(test_str, "/home/al-user") == 'filename'

    test_str = '////./..//../../../foldername/filename'
    assert path.strip_path_inclusion(test_str, "/home/al-user") == 'filename'

    test_str = 'realfolder/../../../foldername/filename'
    assert path.strip_path_inclusion(test_str, "/home/al-user") == 'filename'

    test_str = '..foldername/..filename'
    assert path.strip_path_inclusion(test_str, "/home/al-user") == '..foldername/..filename'

    test_str = '.././//./..//../../../foldername/../../././//../filename'
    assert path.strip_path_inclusion(test_str, "/home/al-user") == 'filename'
