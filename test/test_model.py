from assemblyline.common import forge
from assemblyline.odm.models.config import DEFAULT_CONFIG


def test_config_model():
    config = forge.get_config()
    assert config.as_primitives() == DEFAULT_CONFIG
