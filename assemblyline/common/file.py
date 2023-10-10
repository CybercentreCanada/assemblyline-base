import tempfile
import yaml

from assemblyline.common.identify import CUSTOM_URI_ID


def make_uri_file(directory: str, uri: str, params=None) -> str:
    with tempfile.NamedTemporaryFile(dir=directory, delete=False, mode="w") as out:
        out.write(CUSTOM_URI_ID)
        yaml.dump({"uri": uri}, out)
        if params:
            yaml.dump(params, out)
    return out.name


def normalize_uri_file(directory: str, filename: str) -> str:
    with open(filename, "r") as f:
        data = yaml.safe_load(f)
    uri = data.pop("uri")
    return make_uri_file(directory, uri, data)
