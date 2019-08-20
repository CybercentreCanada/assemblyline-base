from typing import Optional as Opt
from datetime import datetime
from assemblyline import odm

STATUSES = {'INITIALIZING', 'WAITING', 'PROCESSING', 'RESULT_FOUND', 'ERROR_FOUND'}


@odm.model(index=True, store=False)
class Current(odm.Model):
    status: str = odm.Enum(values=STATUSES, default='INITIALIZING')  # Status of the client
    task_sid: Opt[str] = odm.Optional(odm.UUID())                    # SID of the task currently assigned to the client
    task_timeout: Opt[datetime] = odm.Optional(odm.Date())           # Time the task was assigned to the client


@odm.model(index=True, store=True)
class ServiceClient(odm.Model):
    client_id: str = odm.Keyword()                           # Session ID of the client
    container_id: str = odm.Keyword()                        # Docker container ID of the client
    ip: str = odm.IP()                                       # IP address of the client
    service_name: str = odm.Keyword()                        # Name of the service running on the client
    service_version: str = odm.Keyword()                     # Version of the service running on the client
    service_tool_version: Opt[str] = odm.Optional(odm.Keyword())  # Tool version of the service running on the client
    service_timeout: int = odm.Integer()                          # Timeout of the service running on the client
    current: Opt[Current] = odm.Optional(odm.Compound(Current))   # Info about the current status and task assigned to the client
    tasking_counters = odm.Optional(odm.Any())                    # MetricsFactory counters for the service and service_timing
