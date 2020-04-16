
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


@odm.model(index=True, store=True)
class Response(odm.Model):
    message = odm.Text(copyto="__text__")                                # Error message
    service_debug_info = odm.Optional(odm.Keyword())                     # Info about where the service was processed
    service_name = odm.Keyword(copyto="__text__")                        # Name of the service that had an error
    service_tool_version = odm.Optional(odm.Keyword(copyto="__text__"))  # Tool version of the service
    service_version = odm.Keyword()                                      # Version of the service
    status = odm.Enum(values=STATUSES)                                   # Status of the error


@odm.model(index=True, store=True)
class Error(odm.Model):
    archive_ts = odm.Date(store=False)                                     # Archiving timestamp
    created = odm.Date(default="NOW")                                      # Date at which the error was created
    expiry_ts = odm.Optional(odm.Date(store=False))                        # Expiry time stamp
    response: Response = odm.Compound(Response)                            # Response from the service
    sha256 = odm.SHA256(copyto="__text__")                                 # Hash of the file the error is related to
    type = odm.Enum(values=list(ERROR_TYPES.keys()), default="EXCEPTION")  # Type of error

    def build_key(self, service_tool_version=None, task=None):
        key_list = [
            self.sha256,
            self.response.service_name.replace('.', '_'),
            f"v{self.response.service_version.replace('.', '_')}",
            f"c{generate_conf_key(service_tool_version=service_tool_version, task=task)}",
            f"e{ERROR_TYPES.get(self.type, 0)}"]

        return '.'.join(key_list)
