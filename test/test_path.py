from assemblyline.common import path


def test_strip_path_injection_linux():
    test_str = '/home/al-user/filename'
    assert path.strip_path_inclusion(test_str, "/home/al-user") == '/home/al-user/filename'

    test_str = '/home/al-user/'
    assert path.strip_path_inclusion(test_str, "/home/al-user") == '/home/al-user/'

    test_str = '/home/al-user'
    assert path.strip_path_inclusion(test_str, "/home/al-user") == '/home/al-user'

    test_str = '/home/al-user/filename'
    assert path.strip_path_inclusion(test_str, "/home/al-user/") == '/home/al-user/filename'

    test_str = '/home/al-user/'
    assert path.strip_path_inclusion(test_str, "/home/al-user/") == '/home/al-user/'

    test_str = '/home/al-user'
    assert path.strip_path_inclusion(test_str, "/home/al-user/") == '/home/al-user'

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

    test_str = '/home/user_evil/x'
    assert path.strip_path_inclusion(test_str, "/home/al_user") == 'x'

    test_str = '/home/al_user_evil/x'
    assert path.strip_path_inclusion(test_str, "/home/al_user") == 'x'
