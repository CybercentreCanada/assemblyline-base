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
    accepts = odm.Keyword(store=True, default=DEFAULT_SERVICE_ACCEPTS)
    category = odm.Keyword(store=True, default="Static Analysis")
    class_name = odm.Keyword()
    classpath = odm.Keyword(store=True)
    config = odm.Mapping(odm.Any(), default={})
    cpu_cores = odm.Float(default=1.0)
    description = odm.Text(store=True, default="N/A")
    enabled = odm.Boolean(store=True, default=False)
    install_by_default = odm.Boolean(default=False)
    is_external = odm.Boolean(default=False)
    licence_count = odm.Integer(default=0)
    name = odm.Keyword(store=True)
    ram_mb = odm.Integer(default=1024)
    realm = odm.Keyword()
    rejects = odm.Keyword(store=True, default=DEFAULT_SERVICE_REJECTS)
    repo = odm.Keyword()
    stage = odm.Keyword(store=True, default="CORE")
    submission_params = odm.List(odm.Compound(SubmissionParams), index=False, default=[])
    supported_platforms = odm.List(odm.Enum(values=["windows", "linux"]), default=["linux"])
    timeout = odm.Integer(default=60)
