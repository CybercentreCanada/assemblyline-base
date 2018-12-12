from assemblyline import odm

STATUSES = {"FAIL_NONRECOVERABLE", "FAIL_RECOVERABLE"}


@odm.model(index=True, store=True)
class Response(odm.Model):            # Response block
    message = odm.Text()                # Error message
    service_debug_info = odm.Keyword()  # Debug information about where the service was processed
    service_name = odm.Keyword()        # Name of the service that had an error
    service_version = odm.Keyword()     # Version of the service which resulted in an error
    status = odm.Enum(values=STATUSES)  # Status of the error


@odm.model(index=True, store=True)
class Error(odm.Model):
    created = odm.Date()               # Date at which the error was created
    response = odm.Compound(Response)  # Response from the service
    sha256 = odm.Keyword()             # Hash of the file the error is related to
