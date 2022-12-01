
import logging


from assemblyline.common import forge
from assemblyline.common.identify import Identify
from assemblyline.datastore.collection import ESCollection
from assemblyline.datastore.helper import AssemblylineDatastore
from assemblyline.filestore import FileStore
from assemblyline.odm.messages.submission import SubmissionMessage, Submission
from assemblyline.odm.models.config import Config
from assemblyline.remote.datatypes import get_client
from assemblyline.remote.datatypes.queues.comms import CommsQueue
from assemblyline.remote.datatypes.queues.named import NamedQueue

from assemblyline_core.dispatching.schedules import Scheduler
from assemblyline_core.submission_client import SubmissionClient, SubmissionException

ARCHIVE_QUEUE_NAME = 'm-archive'


class ArchiveManager():
    def __init__(
            self, config: Config = None, datastore: AssemblylineDatastore = None, filestore: FileStore = None,
            identify: Identify = None):
        self.log = logging.getLogger('assemblyline.archive_manager')
        self.config = config or forge.get_config()
        if self.config.datastore.archive.enabled:
            self.datastore = datastore or forge.get_datastore(self.config)
            self.filestore = filestore or forge.get_filestore(self.config)
            self.identify = identify or forge.get_identify(config=self.config, datastore=self.datastore, use_cache=True)
            redis_persistent = get_client(self.config.core.redis.persistent.host,
                                          self.config.core.redis.persistent.port, False)
            redis = get_client(self.config.core.redis.nonpersistent.host,
                               self.config.core.redis.nonpersistent.port, False)
            self.archive_queue: NamedQueue[dict] = NamedQueue(ARCHIVE_QUEUE_NAME, redis_persistent)
            self.scheduler = Scheduler(self.datastore, self.config, redis)
            self.submission_traffic = CommsQueue('submissions', host=redis)

    def archive_submission(self, submission, delete_after: bool = False):
        if self.config.datastore.archive.enabled:
            sub_selected = self.scheduler.expand_categories(submission['params']['services']['selected'])
            min_selected = self.scheduler.expand_categories(self.config.core.archiver.minimum_required_services)

            if set(min_selected).issubset(set(sub_selected)):
                self.archive_queue.push(('submission', submission['sid'], delete_after))
                return {"action": "archive"}
            else:
                params = submission['params']
                params['auto_archive'] = True
                params['delete_after_archive'] = delete_after
                params['services']['selected'] = list(set(sub_selected).union(set(min_selected)))
                try:
                    submission_obj = Submission({
                        "files": submission["files"],
                        "metadata": submission['metadata'],
                        "params": params
                    })

                    submit_result = SubmissionClient(datastore=self.datastore, filestore=self.filestore,
                                                     config=self.config, identify=self.identify).submit(submission_obj)
                except (ValueError, KeyError) as e:
                    raise SubmissionException(f"Could not generate re-submission message: {str(e)}").with_traceback()

                self.submission_traffic.publish(SubmissionMessage({
                    'msg': submission_obj,
                    'msg_type': 'SubmissionReceived',
                    'sender': 'ui',
                }).as_primitives())

                # Update current record
                self.datastore.submission.update(submission['sid'], [(ESCollection.UPDATE_SET, 'archived', True)])

                return {"action": "resubmit", "sid": submit_result['sid']}
        else:
            self.log.warning("Trying to archive a submission when archiving is disabled.")
