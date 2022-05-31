from assemblyline.odm import keyword, optional
from assemblyline import odm


@odm.model(index=False, store=False, description="Named Value")
class NamedValue(odm.Model):
    name = keyword(description="Name")
    value = keyword(description="Value")


@odm.model(index=False, store=False, description="Webhook Configuration")
class Webhook(odm.Model):
    password = optional(keyword(default=""), description="Password used to authenticate with source")
    ca_cert = optional(keyword(default=""), description="CA cert for source")
    ssl_ignore_errors = odm.boolean(default=False, description="Ignore SSL errors when reaching out to source?")
    proxy = optional(keyword(default=""), description="Proxy server for source")
    uri = keyword(description="URI to source")
    username = optional(keyword(default=""), description="Username used to authenticate with source")
    headers = odm.sequence(odm.compound(NamedValue), default=[], description="Headers")
    retries = odm.Integer(default=3)


@odm.model(index=False, store=False, description="Resubmission Options")
class ResubmitOptions(odm.Model):
    additional_services = odm.List(odm.Keyword())
    random_below = optional(odm.Integer())


@odm.model(index=False, store=False, description="Postprocessing Action")
class PostprocessAction(odm.Model):
    enabled = odm.boolean(default=False, description="Is this action active")
    run_on_cache = odm.boolean(default=False, description="Should this action run on cache hits")
    run_on_completed = odm.boolean(default=False, description="Should this action run on newly completed submissions")
    filter = keyword(description="Query string to select submissions")
    webhook = optional(odm.compound(Webhook), description="Webhook action configuration")
    raise_alert = odm.boolean(default=False, description="")
    resubmit = optional(odm.compound(ResubmitOptions), description="Resubmission configuration")


DEFAULT_POSTPROCESS_ACTIONS = {
    # Raise alerts for all submissions over 500, both on cache hits and submission complete
    'default_alerts': PostprocessAction(dict(
        enabled=True,
        run_on_cache=True,
        run_on_complete=True,
        filter="max_score: >=500",
        webhook=None,
        raise_alert=True,
        resubmit=None
    )),
    # Resubmit submissions on completion. All submissions with score >= 0 are elegable, but sampling
    # is applied to scores below 500
    'default_resubmit': PostprocessAction(dict(
        enabled=True,
        run_on_cache=False,
        run_on_complete=True,
        filter="max_score: >=0",
        webhook=None,
        raise_alert=False,
        resubmit=ResubmitOptions(dict(
            additional_services=[],
            random_below=500
        ))
    ))
}