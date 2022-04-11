from typing import List

from assemblyline import odm


@odm.model(index=False, store=False)
class ClientOptions(odm.Model):
    host: str = odm.Keyword()
    user: str = odm.Keyword()
    apikey: str = odm.Keyword()
    verify: bool = odm.Boolean()


DEFAULT_CLIENT_OPTIONS = {
    'host': 'https://localhost:443',
    'user': 'admin',
    'apikey': 'devkey:devpass',
    'verify': True
}


@odm.model(index=False, store=False)
class Client(odm.Model):
    type: str = odm.Enum(['api', 'direct'])
    options = odm.Optional(odm.Compound(ClientOptions, default=DEFAULT_CLIENT_OPTIONS))


DEFAULT_CLIENT = {
    'type': 'api',
    'options': DEFAULT_CLIENT_OPTIONS
}


@odm.model(index=False, store=False)
class InputModule(odm.Model):
    enabled: bool = odm.Boolean()
    threads: int = odm.Integer()
    filter_queries = odm.List(odm.Keyword())


DEFAULT_ALERT_INPUT = {
    'enabled': True,
    'threads': 6,
    'filter_queries': [
        'NOT extended_scan:submitted',
        'workflows_completed:true'
    ]
}

DEFAULT_SUBMISSION_INPUT = {
    'enabled': True,
    'threads': 6,
    'filter_queries': [
        'metadata.replay:requested'
    ]
}


@odm.model(index=False, store=False)
class Creator(odm.Model):
    client = odm.Compound(Client, default=DEFAULT_CLIENT)
    alert_input = odm.Compound(InputModule, default=DEFAULT_ALERT_INPUT)
    submission_input = odm.Compound(InputModule, default=DEFAULT_SUBMISSION_INPUT)
    lookback_time: str = odm.Keyword()
    output_filestore: str = odm.Keyword()
    working_directory: str = odm.Keyword()


DEFAULT_CREATOR = {
    'client': DEFAULT_CLIENT,
    'alert_input': DEFAULT_ALERT_INPUT,
    'submission_input': DEFAULT_SUBMISSION_INPUT,
    'lookback_time': '*',
    'output_filestore': 'file:///tmp/replay/output',
    'working_directory': '/tmp/replay/work',
}


@odm.model(index=False, store=False)
class Loader(odm.Model):
    client = odm.Compound(Client, default=DEFAULT_CLIENT)
    failed_directory: str = odm.Keyword()
    input_threads: int = odm.Integer()
    input_directory: str = odm.Keyword()
    min_classification: str = odm.Optional(odm.Keyword())
    rescan: List[str] = odm.List(odm.Keyword())
    working_directory: str = odm.Keyword()


DEFAULT_LOADER = {
    'client': DEFAULT_CLIENT,
    'failed_directory': '/tmp/replay/failed',
    'input_threads': 6,
    'input_directory': '/tmp/replay/input',
    'min_classification': None,
    'rescan': [],
    'working_directory': '/tmp/replay/work',
}


@odm.model(index=False, store=False)
class ReplayConfig(odm.Model):
    creator: Creator = odm.Compound(Creator, default=DEFAULT_CREATOR, description="Replay creator options")
    loader: Loader = odm.Compound(Loader, default=DEFAULT_LOADER, description="Replay loader options")


DEFAULT_REPLAY = {
    "creator": DEFAULT_CREATOR,
    "loader": DEFAULT_LOADER,
}


if __name__ == "__main__":
    # When executed, the replay model will print the default values of the configuration
    import yaml
    print(yaml.safe_dump(ReplayConfig(DEFAULT_REPLAY).as_primitives()))
