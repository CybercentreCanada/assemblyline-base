import enum
import os
from assemblyline.common.path import modulepath


SUBMISSION_QUEUE = 'dispatch-submission-queue'
DISPATCH_TASK_HASH = 'dispatch-active-submissions'
DISPATCH_RUNNING_TASK_HASH = 'dispatch-active-tasks'
SCALER_TIMEOUT_QUEUE = 'scaler-timeout-queue'
CONFIG_HASH = 'al-config'
POST_PROCESS_CONFIG_KEY = 'post-process-actions'


# Some pure functions for getting queue lengths (effectively for appending/prepending constants to strings)
def service_queue_name(service: str) -> str:
    """Take the name of a service, and provide the queue name to send tasks to that service."""
    return 'service-queue-' + service


def make_watcher_list_name(sid: str) -> str:
    """Get the name of the list dispatcher will pull for sending out submission events."""
    return 'dispatch-watcher-list-' + sid


def get_temporary_submission_data_name(sid: str, file_hash: str) -> str:
    """The HashMap used for tracking auxiliary processing data."""
    return '/'.join((sid, file_hash, 'temp_data'))


def get_tag_set_name(sid: str, file_hash: str) -> str:
    """The HashSet used to track the tags for an in-process file."""
    return '/'.join((sid, file_hash, 'tags'))


# A table storing information about the state of a service, expected type is ExpiringHash
# with a default ttl of None, and the ttl set per field based on the timeouts of queries
# and service operation
class ServiceStatus(enum.IntEnum):
    Idle = 0
    Running = 1


SERVICE_STATE_HASH = 'service-stasis-table'

# A null empty accepts, accepts all. A null rejects, rejects nothing
DEFAULT_SERVICE_ACCEPTS = ".*"
DEFAULT_SERVICE_REJECTS = "empty|metadata/.*"

# Queue priority values for each bucket in the ingester
PRIORITIES = {
    'low': 100,  # 0 -> 100
    'medium': 200,  # 101 -> 200
    'high': 300,
    'critical': 400,
    'user-low': 500,
    'user-medium': 1000,
    'user-high': 1500
}
MAX_PRIORITY = 2000

# The above priority values presented as a range for consistency
PRIORITY_RANGES = {}
_start = -1
for _end, _level in sorted((val, key) for key, val in PRIORITIES.items()):
    PRIORITY_RANGES[_level] = (_start + 1, _end)
    _start = _end


# Score thresholds for determining which queue priority a reingested item
# gets based on its previous score.
# eg.: item with a previous score of 99 will get 'low' priority
#      item with a previous score of 300 will get a 'high' priority
PRIORITY_THRESHOLDS = {
    'critical': 500,
    'high': 100,
}

MAGIC_RULE_PATH = os.path.join(modulepath(__name__), 'custom.magic')
YARA_RULE_PATH = os.path.join(modulepath(__name__), 'custom.yara')
