
from json import loads
from os import path, walk
from assemblyline.common.identify import fileinfo


def test_id_file_base():

    tests_dir = path.dirname(__file__)
    id_file_base = "id_file_base"
    file_base_dir = path.join(tests_dir, id_file_base)
    map_file = "id_file_base.json"
    map_path = path.join(file_base_dir, map_file)
    with open(map_path, "r") as f:
        contents = f.read()
        json_contents = loads(contents)
    for _, _, files in walk(file_base_dir):
        for file_name in files:
            if file_name == map_file:
                continue

            file_path = path.join(file_base_dir, file_name)
            data = fileinfo(file_path)
            actual_value = data.get("type", "")
            expected_value = json_contents[file_name]
            assert actual_value == expected_value
