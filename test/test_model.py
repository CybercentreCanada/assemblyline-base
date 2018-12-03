from assemblyline.odm.models.config import get_config, DEFAULT_CONFIG

def test_config_model():
    config = get_config()
    assert config.as_primitives() == DEFAULT_CONFIG
