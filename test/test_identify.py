
import os
import pytest

from cart import unpack_file
from json import loads
from pathlib import Path

from assemblyline.common import forge

SAMPLES_LOCATION = os.environ.get("SAMPLES_LOCATION", None)


def test_id_file_base():
    with forge.get_identify(use_cache=False) as identify:
        tests_dir = os.path.dirname(__file__)
        id_file_base = "id_file_base"
        file_base_dir = os.path.join(tests_dir, id_file_base)
        map_file = "id_file_base.json"
        map_path = os.path.join(file_base_dir, map_file)
        with open(map_path, "r") as f:
            contents = f.read()
            json_contents = loads(contents)
        for _, _, files in os.walk(file_base_dir):
            for file_name in files:
                if file_name == map_file:
                    continue

                file_path = os.path.join(file_base_dir, file_name)
                data = identify.fileinfo(file_path)
                actual_value = data.get("type", "")
                expected_value = json_contents[file_name]
                assert actual_value == expected_value


def get_ids(filepath):
    if not isinstance(filepath, (str, bytes, os.PathLike)):
        return "skipped"
    return "-".join(split_sample(filepath))


def split_sample(filepath):
    target_file = os.path.join("/tmp", os.path.basename(filepath).rstrip(".cart"))
    identify_result = str(filepath.relative_to(Path(SAMPLES_LOCATION)).parent)
    return (target_file, identify_result)


@pytest.fixture()
def sample(request):
    target_file, identify_result = split_sample(request.param)
    try:
        unpack_file(request.param, target_file)
        yield (target_file, identify_result)
    finally:
        if target_file:
            os.unlink(target_file)


if SAMPLES_LOCATION:
    @pytest.mark.parametrize("sample", Path(SAMPLES_LOCATION).rglob("*.cart"), ids=get_ids, indirect=True)
    def test_identify_samples(sample):
        with forge.get_identify(use_cache=False) as identify:
            assert identify.fileinfo(sample[0])["type"] == sample[1]
