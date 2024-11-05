
import json
import logging
import tempfile
import time
from typing import Union

import requests
from assemblyline.common import forge
from assemblyline.common.identify import Identify
from assemblyline.datastore.collection import ESCollection
from assemblyline.datastore.helper import AssemblylineDatastore
from assemblyline.filestore import FileStore
from assemblyline.odm.messages.submission import Submission, SubmissionMessage
from assemblyline.odm.models.config import Config
from assemblyline.remote.datatypes import get_client
from assemblyline.remote.datatypes.queues.comms import CommsQueue
from assemblyline.remote.datatypes.queues.named import NamedQueue

try:
    from assemblyline_core.dispatching.schedules import Scheduler
    from assemblyline_core.submission_client import SubmissionClient, SubmissionException
except ImportError:
    Scheduler = SubmissionClient = SubmissionException = None

ARCHIVE_QUEUE_NAME = 'm-archive'
RETRY_MAX_BACKOFF = 5


class ArchiveManager():
    def __init__(
            self, config: Config = None, datastore: AssemblylineDatastore = None, filestore: FileStore = None,
            identify: Identify = None):
        self.log = logging.getLogger('assemblyline.archive_manager')
        self.config = config or forge.get_config()
        if self.config.datastore.archive.enabled and Scheduler:
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

    def archive_submission(self, submission, delete_after: bool = False, metadata=None, skip_hook=False,
                           use_alternate_dtl=False):
        if self.config.datastore.archive.enabled and Scheduler:
            sub_selected = self.scheduler.expand_categories(submission['params']['services']['selected'])
            min_selected = self.scheduler.expand_categories(self.config.core.archiver.minimum_required_services)

            if set(min_selected).issubset(set(sub_selected)):
                # Should we send it to a webhook ?
                if self.config.core.archiver.use_webhook and not skip_hook:
                    return {"action": "hooked", "success": self._process_hook(submission, delete_after,
                                                                              metadata, use_alternate_dtl)}

                self.archive_queue.push(('submission', submission['sid'], delete_after, metadata, use_alternate_dtl))
                return {"action": "archive", "success": True}
            else:
                params = submission['params']
                params['auto_archive'] = True
                params['delete_after_archive'] = delete_after
                params['use_archive_alternate_dtl'] = use_alternate_dtl
                params['services']['selected'] = list(set(sub_selected).union(set(min_selected)))
                if metadata and self.config.submission.metadata.archive:
                    submission['metadata'].update({k: v for k, v in metadata.items()
                                                  if k not in submission['metadata']})
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

                return {"action": "resubmit", "sid": submit_result['sid'], "success": True}
        else:
            self.log.warning("Trying to archive a submission when archiving is disabled.")

    def _process_hook(self, submission: Submission, delete_after: bool = False, metadata=None, use_alternate_dtl=False):
        backoff = 0.0
        cafile = None
        hook = self.config.core.archiver.webhook

        try:
            payload = json.dumps({
                'delete_after': delete_after,
                'metadata': metadata,
                'submission': submission,
                'use_alternate_dtl': use_alternate_dtl
            })

            # Setup auth headers and other headers
            auth = None
            if hook.username and hook.password:
                auth = requests.auth.BasicAuth(login=hook.username, password=hook.password)
            headers = {head.name: head.value for head in hook.headers}
            headers.setdefault('Content-Type', 'application/json')

            # Setup ssl details
            verify: Union[None, bool, str] = None
            proxies = None
            if hook.ssl_ignore_errors:
                verify = False
            if hook.ca_cert:
                cafile = tempfile.NamedTemporaryFile()
                cafile.write(hook.ca_cert.encode())
                cafile.flush()
                verify = cafile.name
            if hook.proxy:
                proxies = {
                    "http": hook.proxy,
                    "https": hook.proxy
                }

            # Setup setup http query details
            with requests.session() as session:
                # Setup session
                session.auth = auth
                session.headers.update(headers)

                # Loop up to retry limit
                for _ in range(hook.retries):
                    # Wait before retrying, 0 first time, so we can have this before the post
                    # and not wait after the final failure
                    time.sleep(backoff)
                    backoff = min(RETRY_MAX_BACKOFF, backoff * 2) + 0.1

                    # Try posting to the webhook once. If it succeeds return and let
                    # the withs and finallys finish all the cleanup
                    try:
                        resp = session.request(hook.method, hook.uri, data=payload,
                                               verify=verify, proxies=proxies)
                        resp.raise_for_status()
                        return True
                    except Exception:
                        self.log.exception(f"Error pushing to webhook: {hook}")

        except Exception:
            self.log.exception(f"Error reading webhook configuration: {hook}")
        finally:
            if cafile is not None:
                cafile.close()

        return False
