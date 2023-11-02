from assemblyline.common.file import make_uri_file, normalize_uri_file
import tempfile


def test_make_uri_file():
    expected_file = "# Assemblyline URI file\nuri: http://canada.ca\n"
    with tempfile.TemporaryDirectory() as tempdir:
        filepath = make_uri_file(tempdir, "http://canada.ca")
        with open(filepath, "r") as f:
            assert f.read() == expected_file

    expected_file = "# Assemblyline URI file\nuri: http://canada.ca\nA: 1\nB: 2\n"
    with tempfile.TemporaryDirectory() as tempdir:
        filepath = make_uri_file(tempdir, "http://canada.ca", {"A": 1, "B": 2})
        with open(filepath, "r") as f:
            assert f.read() == expected_file

    with tempfile.TemporaryDirectory() as tempdir:
        filepath = make_uri_file(tempdir, "http://canada.ca", {"B": 2, "A": 1})
        with open(filepath, "r") as f:
            assert f.read() == expected_file

    expected_file = "# Assemblyline URI file\nuri: http://canada.ca\nA:\n  A1: 1\n  A2: 2\n"
    with tempfile.TemporaryDirectory() as tempdir:
        filepath = make_uri_file(tempdir, "http://canada.ca", {"A": {"A1": 1, "A2": 2}})
        with open(filepath, "r") as f:
            assert f.read() == expected_file

    with tempfile.TemporaryDirectory() as tempdir:
        filepath = make_uri_file(tempdir, "http://canada.ca", {"A": {"A2": 2, "A1": 1}})
        with open(filepath, "r") as f:
            assert f.read() == expected_file


def test_normalize_uri_file():
    input_file = "# Assemblyline URI file\nuri: http://canada.ca\nA: 1\nB: 2\n"
    expected_file = "# Assemblyline URI file\nuri: http://canada.ca\nA: 1\nB: 2\n"
    with tempfile.TemporaryDirectory() as tempdir:
        with tempfile.NamedTemporaryFile(dir=tempdir, delete=False, mode="w") as f:
            f.write(input_file)
        filepath = normalize_uri_file(tempdir, f.name)
        with open(filepath, "r") as f:
            assert f.read() == expected_file

    input_file = "# Assemblyline URI file\nuri: http://canada.ca\nB: 2\nA: 1\n"
    expected_file = "# Assemblyline URI file\nuri: http://canada.ca\nA: 1\nB: 2\n"
    with tempfile.TemporaryDirectory() as tempdir:
        with tempfile.NamedTemporaryFile(dir=tempdir, delete=False, mode="w") as f:
            f.write(input_file)
        filepath = normalize_uri_file(tempdir, f.name)
        with open(filepath, "r") as f:
            assert f.read() == expected_file

    input_file = "# Assemblyline URI file\nuri: http://canada.ca\nA:\n  A1: 1\n  A2: 2\n"
    expected_file = "# Assemblyline URI file\nuri: http://canada.ca\nA:\n  A1: 1\n  A2: 2\n"
    with tempfile.TemporaryDirectory() as tempdir:
        with tempfile.NamedTemporaryFile(dir=tempdir, delete=False, mode="w") as f:
            f.write(input_file)
        filepath = normalize_uri_file(tempdir, f.name)
        with open(filepath, "r") as f:
            assert f.read() == expected_file

    input_file = "# Assemblyline URI file\nuri: http://canada.ca\nA:\n  A2: 2\n  A1: 1\n"
    expected_file = "# Assemblyline URI file\nuri: http://canada.ca\nA:\n  A1: 1\n  A2: 2\n"
    with tempfile.TemporaryDirectory() as tempdir:
        with tempfile.NamedTemporaryFile(dir=tempdir, delete=False, mode="w") as f:
            f.write(input_file)
        filepath = normalize_uri_file(tempdir, f.name)
        with open(filepath, "r") as f:
            assert f.read() == expected_file
