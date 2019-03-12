from assemblyline import odm
from assemblyline.common.constants import DEFAULT_SERVICE_ACCEPTS, DEFAULT_SERVICE_REJECTS


@odm.model(index=False, store=False)
class SubmissionParams(odm.Model):
    default = odm.Any()
    name = odm.Keyword()
    type = odm.Enum(values=['str', 'int', 'list', 'bool'])
    value = odm.Any()


@odm.model(index=True, store=False)
class Service(odm.Model):
    # Regexes applied to assemblyline style file type string
    accepts = odm.Keyword(store=True, default=DEFAULT_SERVICE_ACCEPTS, default_set=True)
    rejects = odm.Keyword(store=True, default=DEFAULT_SERVICE_REJECTS, default_set=True)

    category = odm.Keyword(store=True, default="Static Analysis")
    config = odm.Mapping(odm.Any(), default={})
    cpu_cores = odm.Float(default=1.0)
    description = odm.Text(store=True, default="NA")
    enabled = odm.Boolean(store=True, default=False)
    install_by_default = odm.Boolean(default=False)
    is_external = odm.Boolean(default=False)
    licence_count = odm.Integer(default=0)

    name = odm.Keyword(store=True)
    version = odm.Keyword(store=True)

    ram_mb = odm.Integer(default=1024)

    # Should the result cache be disabled for this service
    disable_cache = odm.Boolean(default=False)

    stage = odm.Keyword(store=True, default="CORE")
    submission_params = odm.List(odm.Compound(SubmissionParams), index=False, default=[])
    supported_platforms = odm.List(odm.Enum(values=["windows", "linux"]), default=["linux"])
    timeout = odm.Integer(default=60)
