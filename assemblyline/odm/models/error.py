
from assemblyline import odm
from assemblyline.common.caching import generate_conf_key

STATUSES = {"FAIL_NONRECOVERABLE", "FAIL_RECOVERABLE"}
ERROR_TYPES = {
    "UNKNOWN": 0,
    "EXCEPTION": 1,
    "MAX DEPTH REACHED": 10,
    "MAX FILES REACHED": 11,
    "MAX RETRY REACHED": 12,
    "SERVICE BUSY": 20,
    "SERVICE DOWN": 21,
    "TASK PRE-EMPTED": 30
}


@odm.model(index=True, store=True, description="Error Response from a Service")
class Response(odm.Model):
    message = odm.Text(copyto="__text__", description="Error message")
    service_debug_info = odm.Optional(odm.Keyword(), description="Information about where the service was processed")
    service_name = odm.Keyword(copyto="__text__", description="Service Name")
    service_tool_version = odm.Optional(odm.Keyword(copyto="__text__"), description="Service Tool Version")
    service_version = odm.Keyword(description="Service Version")
    status = odm.Enum(values=STATUSES, description="Status of error produced by service")


@odm.model(index=True, store=True, description="Error Model used by Error Viewer")
class Error(odm.Model):
    archive_ts = odm.Optional(odm.Date(store=False, description="Archiving timestamp"))
    created = odm.Date(default="NOW", description="Error creation timestamp")
    expiry_ts = odm.Optional(odm.Date(store=False), description="Expiry timestamp")
    response: Response = odm.Compound(Response, description="Response from the service")
    sha256 = odm.SHA256(copyto="__text__", description="SHA256 of file related to service error")
    type = odm.Enum(values=list(ERROR_TYPES.keys()), default="EXCEPTION", description="Type of error")

    def build_key(self, service_tool_version=None, task=None):
        key_list = [
            self.sha256,
            self.response.service_name.replace('.', '_'),
            f"v{self.response.service_version.replace('.', '_')}",
            f"c{generate_conf_key(service_tool_version=service_tool_version, task=task)}",
            f"e{ERROR_TYPES.get(self.type, 0)}"]

        return '.'.join(key_list)
