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
    type: str = odm.Enum(['api', 'direct'], description="Type of client to use for Replay operations")
    options = odm.Optional(odm.Compound(ClientOptions, default=DEFAULT_CLIENT_OPTIONS),
                           description="Options for the client")


DEFAULT_CLIENT = {
    'type': 'direct',
    'options': DEFAULT_CLIENT_OPTIONS
}


@odm.model(index=False, store=False, description="Input module configuration model for Replay creator operations")
class InputModule(odm.Model):
    enabled: bool = odm.Boolean(description="Is this input module enabled?")
    threads: int = odm.Integer(description="Number of threads to use for this input module",)
    filter_queries = odm.List(odm.Keyword(), description="List of filter queries to apply to this input module")


DEFAULT_INPUT = {
    'enabled': True,
    'threads': 6,
    'filter_queries': []
}

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


@odm.model(index=False, store=False, description="Replay creator configuration model")
class Creator(odm.Model):
    client = odm.Compound(Client, default=DEFAULT_CLIENT, description="Client to use for Replay operations")
    alert_input = odm.Compound(InputModule, default=DEFAULT_ALERT_INPUT, description="Input module for alerts")
    badlist_input = odm.Compound(InputModule, default=DEFAULT_INPUT, description="Input module for badlist items")
    safelist_input = odm.Compound(InputModule, default=DEFAULT_INPUT, description="Input module for safelist items")
    signature_input = odm.Compound(InputModule, default=DEFAULT_INPUT, description="Input module for signatures")
    submission_input = odm.Compound(InputModule, default=DEFAULT_SUBMISSION_INPUT,
                                    description="Input module for submissions")
    workflow_input = odm.Compound(InputModule, default=DEFAULT_INPUT, description="Input module for workflows")
    lookback_time: str = odm.Keyword(description="Lookback time for the Replay creator, e.g., '1d' for one day")
    output_filestore: str = odm.Keyword(description="Output filestore URI for the Replay creator, e.g., 'file:///tmp/replay/output'")
    working_directory: str = odm.Keyword(description="Working directory for the Replay creator, e.g., '/tmp/replay/work'")


DEFAULT_CREATOR = {
    'client': DEFAULT_CLIENT,
    'alert_input': DEFAULT_ALERT_INPUT,
    'badlist_input': DEFAULT_INPUT,
    'safelist_input': DEFAULT_INPUT,
    'submission_input': DEFAULT_SUBMISSION_INPUT,
    'workflow_input': DEFAULT_INPUT,
    'lookback_time': '*',
    'output_filestore': 'file:///tmp/replay/output',
    'working_directory': '/tmp/replay/work',
}


@odm.model(index=False, store=False, description="Replay loader configuration model")
class Loader(odm.Model):
    client = odm.Compound(Client, default=DEFAULT_CLIENT, description="Client to use for Replay loader operations")
    failed_directory: str = odm.Keyword(description="Directory to store failed Replay bundles")
    input_threads: int = odm.Integer(description="Number of threads to use for loading input bundles",)
    input_directory: str = odm.Keyword(description="Directory to load input Replay bundles from")
    min_classification: str = odm.Optional(odm.ClassificationString(), description="Minimum classification level for Replay bundles to be processed")
    reclassification: str = odm.Optional(odm.ClassificationString(), description="Classification level to reclassify Replay bundles to after being imported")
    rescan: List[str] = odm.List(odm.Keyword(), description="List of services to rescan after importing Replay bundles")
    working_directory: str = odm.Keyword(description="Working directory for the Replay loader, e.g., '/tmp/replay/work'")
    sync_check_interval: int = odm.Integer(default=3600,
                                           description='How often to check on imported Replay bundles (in seconds)?')


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
