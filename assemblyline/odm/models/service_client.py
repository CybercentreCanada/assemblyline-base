from assemblyline import odm

STATUSES = {'INITIALIZING', 'WAITING', 'PROCESSING', 'RESULT_FOUND', 'ERROR_FOUND'}


@odm.model(index=True, store=True)
class Current(odm.Model):
    status = odm.Enum(values=STATUSES, default='INITIALIZING')  # Status of the client
    task_sid = odm.Optional(odm.Keyword())                      # SID of the task currently assigned to the client
    task_start_time = odm.Optional(odm.Date())                  # Time the task was assigned to the client


@odm.model(index=True, store=True)
class ServiceClient(odm.Model):
    client_id = odm.Keyword()                       # Session ID of the client
    container_id = odm.Keyword()                    # Docker container ID of the client
    ip = odm.IP()                                   # IP address of the client
    service_name = odm.Keyword()                    # Name of the service running on the client
    service_version = odm.Keyword()                 # Version of the service running on the client
    service_tool_version = odm.Keyword(default='')  # Tool version of the service running on the client
    current = odm.Optional(odm.Compound(Current))   # Info about the current status and task assigned to the client
    tasking_counters = odm.Optional(odm.Any())      # MetricsFactory counters for the service and service_timing
