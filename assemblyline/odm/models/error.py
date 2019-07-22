from assemblyline import odm

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
    service_tool_version = odm.Optional(odm.Keyword(copyto="__text__"))  # Tool version of the service that ran on the file
    service_version = odm.Keyword()                                      # Version of the service which resulted in an error
    status = odm.Enum(values=STATUSES)                                   # Status of the error


@odm.model(index=True, store=True)
class Error(odm.Model):
    created = odm.Date(default="NOW")                                      # Date at which the error was created
    expiry_ts = odm.Date(store=False)                                      # Expiry time stamp
    response: Response = odm.Compound(Response)                            # Response from the service
    sha256 = odm.Keyword(copyto="__text__")                                # Hash of the file the error is related to
    type = odm.Enum(values=list(ERROR_TYPES.keys()), default="EXCEPTION")  # Type of error

    def build_key(self, conf_key=None):
        key_list = [
            self.sha256,
            self.response.service_name.replace('.', '_'),
            f"v{self.response.service_version.replace('.', '_')}"
        ]

        if conf_key:
            key_list.append('c' + conf_key.replace('.', '_'))
        else:
            key_list.append("c0")

        key_list.append(f"e{ERROR_TYPES.get(self.type, 0)}")

        return '.'.join(key_list)
