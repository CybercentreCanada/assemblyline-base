from assemblyline import odm


@odm.model(index=False, store=False)
class SubmissionParams(odm.Model):
    default = odm.Any()
    name = odm.Keyword()
    type = odm.Enum(values=['str', 'int', 'list', 'bool'])
    value = odm.Any()


@odm.model(index=True, store=False)
class Service(odm.Model):
    accepts = odm.Keyword(store=True)
    category = odm.Keyword(store=True)
    class_name = odm.Keyword()
    classpath = odm.Keyword(store=True)
    config = odm.Mapping(odm.Any())
    cpu_cores = odm.Float()
    description = odm.Text(store=True)
    enabled = odm.Boolean(store=True)
    install_by_default = odm.Boolean()
    is_external = odm.Boolean()
    licence_count = odm.Integer()
    name = odm.Keyword(store=True)
    ram_mb = odm.Integer()
    realm = odm.Keyword()
    rejects = odm.Keyword(store=True)
    repo = odm.Keyword()
    stage = odm.Keyword(store=True)
    submission_params = odm.List(odm.Compound(SubmissionParams), index=False)
    supported_platforms = odm.List(odm.Keyword())
    timeout = odm.Integer()
