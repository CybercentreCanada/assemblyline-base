
import logging
import os
import tempfile

from assemblyline.datastore.helper import AssemblylineDatastore
from assemblyline.odm.models.submission import Submission
from assemblyline.filestore import FileStore


log = logging.getLogger('assemblyline.archiver')


class SubmissionNotFound(Exception):
    pass


class FileNotFound(Exception):
    pass


def archive_submission(sid: str, datastore: AssemblylineDatastore, filestore: FileStore, archivestore: FileStore):
    # Load datastore if not there already
    if datastore and not datastore.ds.archive_access:
        raise RuntimeError("Passed datastore does not have archive access.")

    # Load submission
    submission: Submission = datastore.submission.get_from_archive(sid)
    if not submission:
        submission: Submission = datastore.submission.get_if_exists(sid, archive_access=False)
        if not submission:
            raise SubmissionNotFound(f"Submission '{sid}' was not found.")
        # TODO:
        #    Call / wait for webhook
        #    Save it to the archive with extra metadata

        # Reset Expiry
        submission.expiry_ts = None
        datastore.submission.save_to_archive(sid, submission, delete_after=False)

    # Gather list of files and archives them
    files = {f.sha256 for f in submission.files}
    files.update([r[:64] for r in submission.results])
    for sha256 in files:
        datastore.file.archive(sha256)
        if filestore != archivestore:
            with tempfile.NamedTemporaryFile() as buf:
                filestore.download(sha256, buf.name)
                try:
                    if os.path.getsize(buf.name):
                        archivestore.upload(buf.name, sha256)
                except Exception as e:
                    log.error(f"Could not copy file {sha256} from the filestore to the archivestore. ({e})")

    # Archive associated results (Skip emptys)
    for r in submission.results:
        if not r.endswith(".e"):
            datastore.result.archive(r)
