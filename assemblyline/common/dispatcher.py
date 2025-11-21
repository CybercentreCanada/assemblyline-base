from redis import Redis

from assemblyline.remote.datatypes.hash import Hash
from assemblyline.remote.datatypes.queues.named import NamedQueue


DISPATCH_TASK_ASSIGNMENT = 'dispatcher-tasks-assigned-to-'
TASK_ASSIGNMENT_PATTERN = DISPATCH_TASK_ASSIGNMENT + '*'
DISPATCH_START_EVENTS = 'dispatcher-start-events-'
DISPATCH_RESULT_QUEUE = 'dispatcher-results-'
DISPATCH_COMMAND_QUEUE = 'dispatcher-commands-'
DISPATCH_DIRECTORY = 'dispatchers-directory'


class Dispatcher:
    """A utility class for fetching information about the dispatchers running in the system."""
    @staticmethod
    def all_instances(persistent_redis: Redis) -> list[str]:
        """List all dispatchers who have created a listing for themselves."""
        return Hash(DISPATCH_DIRECTORY, host=persistent_redis).keys()

    @staticmethod
    def instance_assignment_size(persistent_redis: Redis, instance_id: str):
        """Get the number of submissions assigned to a given dispatcher instance."""
        return Hash(DISPATCH_TASK_ASSIGNMENT + instance_id, host=persistent_redis).length()

    @staticmethod
    def instance_assignment(persistent_redis: Redis, instance_id: str) -> list[str]:
        """List the submissions assigned to a given dispatcher instance."""
        return Hash(DISPATCH_TASK_ASSIGNMENT + instance_id, host=persistent_redis).keys()

    @staticmethod
    def all_queue_lengths(redis: Redis, instance_id: str):
        """Get the queue lengths for a given dispatcher instance."""
        return {
            'start': NamedQueue(DISPATCH_START_EVENTS + instance_id, host=redis).length(),
            'result': NamedQueue(DISPATCH_RESULT_QUEUE + instance_id, host=redis).length(),
            'command': NamedQueue(DISPATCH_COMMAND_QUEUE + instance_id, host=redis).length()
        }