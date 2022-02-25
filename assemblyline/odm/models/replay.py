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
    filter_queries = odm.List(odm.Keyword())


DEFAULT_ALERT_INPUT = {
    'enabled': True,
    'filter_queries': [
        'NOT extended_scan:submitted'
    ]
}

DEFAULT_SUBMISSION_INPUT = {
    'enabled': True,
    'filter_queries': [
        'metadata.replay:true'
    ]
}


@odm.model(index=False, store=False)
class Creator(odm.Model):
    client = odm.Compound(Client, default=DEFAULT_CLIENT)
    alert_input = odm.Compound(InputModule, default=DEFAULT_ALERT_INPUT)
    submission_input = odm.Compound(InputModule, default=DEFAULT_SUBMISSION_INPUT)
    output_directory: str = odm.Keyword()
    working_directory: str = odm.Keyword()


DEFAULT_CREATOR = {
    'client': DEFAULT_CLIENT,
    'alert_input': DEFAULT_ALERT_INPUT,
    'submission_input': DEFAULT_SUBMISSION_INPUT,
    'output_directory': '/tmp/replay/input',
    'working_directory': '/tmp/replay/work',
}


@odm.model(index=False, store=False)
class Loader(odm.Model):
    input_directory: str = odm.Keyword()
    client = odm.Compound(Client, default=DEFAULT_CLIENT)
    rescan: List[str] = odm.List(odm.Keyword())


DEFAULT_LOADER = {
    'input_directory': '/tmp/replay/input',
    'client': DEFAULT_CLIENT,
    'rescan': []
}


@odm.model(index=False, store=False)
class ReplayConfig(odm.Model):
    # Replay creator options
    creator: Creator = odm.Compound(Creator, default=DEFAULT_CREATOR)
    # Replay loader options
    loader: Loader = odm.Compound(Loader, default=DEFAULT_LOADER)


DEFAULT_REPLAY = {
    "creator": DEFAULT_CREATOR,
    "loader": DEFAULT_LOADER,
}


if __name__ == "__main__":
    # When executed, the replay model will print the default values of the configuration
    import yaml
    print(yaml.safe_dump(ReplayConfig(DEFAULT_REPLAY).as_primitives()))
