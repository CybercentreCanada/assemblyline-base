from assemblyline.odm import keyword, optional, integer, boolean, compound, sequence
from assemblyline import odm


@odm.model(index=False, store=False, description="Named Value")
class NamedValue(odm.Model):
    name = keyword(description="Name")
    value = keyword(description="Value")


@odm.model(index=False, store=False, description="Webhook Configuration")
class Webhook(odm.Model):
    password = optional(keyword(default=""), description="Password used to authenticate with source")
    ca_cert = optional(keyword(default=""), description="CA cert for source")
    ssl_ignore_errors = boolean(default=False, description="Ignore SSL errors when reaching out to source?")
    proxy = optional(keyword(default=""), description="Proxy server for source")
    method = keyword(default='POST', description="HTTP method used to access webhook")
    uri = keyword(description="URI to source")
    username = optional(keyword(default=""), description="Username used to authenticate with source")
    headers = sequence(compound(NamedValue), default=[], description="Headers")
    retries = integer(default=3)


@odm.model(index=False, store=False, description="Resubmission Options")
class ResubmitOptions(odm.Model):
    additional_services = sequence(keyword())
    random_below = optional(integer())


@odm.model(index=False, store=False, description="Postprocessing Action")
class PostprocessAction(odm.Model):
    enabled = boolean(default=False, description="Is this action active")
    run_on_cache = boolean(default=False, description="Should this action run on cache hits")
    run_on_completed = boolean(default=False, description="Should this action run on newly completed submissions")
    filter = keyword(description="Query string to select submissions")
    webhook = optional(compound(Webhook), description="Webhook action configuration")
    raise_alert = boolean(default=False, description="Raise an alert when this action is triggered")
    resubmit = optional(compound(ResubmitOptions), description="Resubmission configuration")
    archive_submission = boolean(default=False, description="Archive the submission when this action is triggered")


DEFAULT_POSTPROCESS_ACTIONS = {
    # Raise alerts for all submissions over 500, both on cache hits and submission complete
    'default_alerts': PostprocessAction(dict(
        enabled=True,
        run_on_cache=True,
        run_on_completed=True,
        filter="max_score: >=500",
        webhook=None,
        raise_alert=True,
        resubmit=None,
        archive_submission=False
    )),
    # Resubmit submissions on completion. All submissions with score >= 0 are elegable, but sampling
    # is applied to scores below 500
    'default_resubmit': PostprocessAction(dict(
        enabled=True,
        run_on_cache=True,
        run_on_completed=True,
        filter="max_score: >=0",
        webhook=None,
        raise_alert=False,
        resubmit=ResubmitOptions(dict(
            additional_services=[],
            random_below=500
        )),
        archive_submission=False
    ))
}
