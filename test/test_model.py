from assemblyline.common import forge
from assemblyline.odm.models import random_model_obj
from assemblyline.odm.models.config import DEFAULT_CONFIG, Config
from assemblyline.odm.models.node import Node
from assemblyline.odm.models.result import Result
from assemblyline.odm.models.submission import Submission


def test_config_model():
    config = forge.get_config()
    assert config.as_primitives() == DEFAULT_CONFIG


def test_generating_models():
    from pprint import pprint
    pprint(random_model_obj(Config).as_primitives())
    pprint(random_model_obj(Node).as_primitives())
    pprint(random_model_obj(Result).as_primitives())
    pprint(random_model_obj(Submission).as_primitives())