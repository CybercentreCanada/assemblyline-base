
import json
import logging
import os
import shutil
import subprocess
import tempfile
import time

from copy import copy
from assemblyline.common.isotime import now_as_iso
from cart import pack_stream, unpack_stream, is_cart

from assemblyline.common import forge
from assemblyline.common.uid import get_random_id
from assemblyline.datastore.exceptions import MultiKeyError
from assemblyline.filestore import FileStoreException
try:
    from assemblyline_core.submission_client import SubmissionClient
except ImportError:
    SubmissionClient = None

config = forge.get_config()
Classification = forge.get_classification()
MAX_RETRY = 10
WORK_DIR = "/tmp/bundling"
BUNDLE_MAGIC = b'\x1f\x8b\x08'
BUNDLE_TYPE = "archive/bundle/al"

log = logging.getLogger('assemblyline.bundling')


class BundlingException(Exception):
    pass


class AlertNotFound(BundlingException):
    pass


class SubmissionNotFound(BundlingException):
    pass


class IncompleteBundle(BundlingException):
    pass


class SubmissionAlreadyExist(BundlingException):
    pass


# noinspection PyBroadException
def format_result(r):
    try:
        title = r['result']['sections'][0]['title_text']
        if title.startswith('Result exceeded max size.'):
            sha256 = r['response']['supplementary'][-1][1]
            with forge.get_filestore() as transport:
                oversized = json.loads(transport.get(sha256))
            oversized['oversized'] = True
            return oversized
    except Exception:  # pylint:disable=W0702
        pass

    return r


def get_results(keys, file_infos_p, storage_p):
    out = {}
    res = {}
    missing = []
    supplementary = set()
    retry = 0
    while keys and retry < MAX_RETRY:
        if retry:
            time.sleep(2 ** (retry - 7))
        try:
            res.update(storage_p.get_multiple_results(keys, Classification, as_obj=False))
        except MultiKeyError as e:
            log.warning(f"Trying to get multiple results but some are missing: {str(e.keys)}")
            res.update(e.partial_output)
            missing.extend(e.keys)
        keys = [x for x in keys if x not in res and x not in missing]
        retry += 1

    results = {}
    for k, v in res.items():
        file_info = file_infos_p.get(k[:64], None)
        if file_info:
            v = format_result(v)
            if v:
                results[k] = v
                # Include supplementary files associated to result
                [supplementary.add(s['sha256']) for s in v['response']['supplementary']]

    out["results"] = results
    out["missing_result_keys"] = keys + missing

    return out, list(supplementary)


def get_errors(keys, storage_p):
    out = {}
    err = {}
    missing = []
    retry = 0
    while keys and retry < MAX_RETRY:
        if retry:
            time.sleep(2 ** (retry - 7))
        try:
            err.update(storage_p.error.multiget(keys, as_obj=False))
        except MultiKeyError as e:
            log.warning(f"Trying to get multiple errors but some are missing: {str(e.keys)}")
            err.update(e.partial_output)
            missing.extend(e.keys)
        keys = [x for x in keys if x not in err and x not in missing]
        retry += 1

    out["errors"] = err
    out["missing_error_keys"] = keys + missing

    return out


def get_file_infos(keys, storage_p):
    infos = {}
    missing = []
    retry = 0
    while keys and retry < MAX_RETRY:
        if retry:
            time.sleep(2 ** (retry - 7))
        try:
            infos.update(storage_p.file.multiget(keys, as_obj=False))
        except MultiKeyError as e:
            log.warning(f"Trying to get multiple files but some are missing: {str(e.keys)}")
            infos.update(e.partial_output)
            missing.extend(e.keys)
        keys = [x for x in keys if x not in infos and x not in missing]
        retry += 1

    return infos, missing


def recursive_flatten_tree(tree):
    sha256s = []

    for key, val in tree.items():
        sha256s.extend(recursive_flatten_tree(val.get('children', {})))
        if key not in sha256s:
            sha256s.append(key)

    return list(set(sha256s))


# noinspection PyBroadException
def create_bundle(sid, working_dir=WORK_DIR, use_alert=False):
    with forge.get_datastore(archive_access=True) as datastore:
        temp_bundle_file = f"bundle_{get_random_id()}"
        current_working_dir = os.path.join(working_dir, temp_bundle_file)
        target_file = os.path.join(working_dir, f"{temp_bundle_file}.cart")
        tgz_file = os.path.join(working_dir, f"{temp_bundle_file}.tgz")
        try:
            if use_alert:
                alert = datastore.alert.get(sid, as_obj=False)
                if alert is None:
                    raise AlertNotFound("Can't find alert %s, skipping." % sid)

                sid = alert['sid']
            else:
                alert = None
            submission = datastore.submission.get(sid, as_obj=False)
            if submission is None and alert is None:
                raise SubmissionNotFound("Can't find submission %s, skipping." % sid)
            else:

                try:
                    os.makedirs(current_working_dir)
                except PermissionError:
                    raise
                except Exception:
                    pass

                data = {}
                if submission:
                    # Create file information data
                    file_tree = datastore.get_or_create_file_tree(submission,
                                                                  config.submission.max_extraction_depth)['tree']
                    flatten_tree = list(set(recursive_flatten_tree(file_tree) +
                                            [r[:64] for r in submission.get("results", [])]))
                    file_infos, _ = get_file_infos(copy(flatten_tree), datastore)

                    # Add bundling metadata
                    if 'bundle.source' not in submission['metadata']:
                        submission['metadata']['bundle.source'] = config.ui.fqdn
                    if 'bundle.created' not in submission['metadata']:
                        submission['metadata']['bundle.created'] = now_as_iso()
                    if Classification.enforce and 'bundle.classification' not in submission['metadata']:
                        submission['metadata']['bundle.classification'] = submission['classification']

                    results, supplementary = get_results(submission.get("results", []), file_infos, datastore)
                    supp_info, _ = get_file_infos(copy(supplementary), datastore)
                    file_infos.update(supp_info)

                    data.update({
                        'submission': submission,
                        'files': {"list": flatten_tree, "tree": file_tree, "infos": file_infos},
                        'results': results,
                        'errors': get_errors(submission.get("errors", []), datastore)
                    })

                    # Download all related files
                    with forge.get_filestore() as filestore:
                        for sha256 in flatten_tree + supplementary:
                            try:
                                filestore.download(sha256, os.path.join(current_working_dir, sha256))
                            except FileStoreException:
                                pass

                if alert:
                    if 'bundle.source' not in alert['metadata']:
                        alert['metadata']['bundle.source'] = config.ui.fqdn
                    if 'bundle.created' not in alert['metadata']:
                        alert['metadata']['bundle.created'] = now_as_iso()
                    if Classification.enforce and 'bundle.classification' not in alert['metadata']:
                        alert['metadata']['bundle.classification'] = alert['classification']
                    data['alert'] = alert

                # Save result files
                with open(os.path.join(current_working_dir, "results.json"), "w") as fp:
                    json.dump(data, fp)

                # Create the bundle
                subprocess.check_call("tar czf %s *" % tgz_file, shell=True, cwd=current_working_dir)

                with open(target_file, 'wb') as oh:
                    with open(tgz_file, 'rb') as ih:
                        pack_stream(ih, oh, {'al': {"type": BUNDLE_TYPE}, 'name': f"{sid}.tgz"})

                return target_file
        except (SubmissionNotFound, AlertNotFound):
            raise
        except Exception as e:
            raise BundlingException("Could not bundle submission '%s'. [%s: %s]" % (sid, type(e).__name__, str(e)))
        finally:
            if os.path.exists(current_working_dir):
                subprocess.check_call(["rm", "-rf", current_working_dir])
            if os.path.exists(tgz_file):
                os.unlink(tgz_file)


# noinspection PyBroadException,PyProtectedMember
def import_bundle(path, working_dir=WORK_DIR, min_classification=Classification.UNRESTRICTED, allow_incomplete=False,
                  rescan_services=None, exist_ok=False, cleanup=True, identify=None):
    with forge.get_datastore(archive_access=True) as datastore:
        current_working_dir = os.path.join(working_dir, get_random_id())
        res_file = os.path.join(current_working_dir, "results.json")
        try:
            os.makedirs(current_working_dir)
        except Exception:
            pass

        with open(path, 'rb') as original_file:
            if is_cart(original_file.read(256)):
                original_file.seek(0)

                extracted_fd, extracted_path = tempfile.mkstemp()
                extracted_file = os.fdopen(extracted_fd, 'wb')

                try:
                    hdr, _ = unpack_stream(original_file, extracted_file)
                    if hdr.get('al', {}).get('type', 'unknown') != BUNDLE_TYPE:
                        raise BundlingException(f"Not a valid CaRTed bundle, should be of type: {BUNDLE_TYPE}")
                finally:
                    extracted_file.close()
            else:
                extracted_path = path

        # Extract  the bundle
        try:
            subprocess.check_call(["tar", "-zxf", extracted_path, "-C", current_working_dir])
        except subprocess.CalledProcessError:
            raise BundlingException("Bundle decompression failed. Not a valid bundle...")

        with open(res_file, 'rb') as fh:
            data = json.load(fh)

        alert = data.get('alert', None)
        submission = data.get('submission', None)

        try:
            if submission:
                sid = submission['sid']

                # Load results, files and errors
                results = data.get('results', None)
                files = data.get('files', None)
                errors = data.get('errors', None)

                # Check if we have all the service results
                for res_key in submission['results']:
                    if results is None or (res_key not in results['results'].keys() and not allow_incomplete):
                        raise IncompleteBundle("Incomplete results in bundle. Skipping %s..." % sid)

                # Check if we have all files
                for sha256 in list(set([x[:64] for x in submission['results']])):
                    if files is None or (sha256 not in files['infos'].keys() and not allow_incomplete):
                        raise IncompleteBundle("Incomplete files in bundle. Skipping %s..." % sid)

                # Check if we all errors
                for err_key in submission['errors']:
                    if errors is None or (err_key not in errors['errors'].keys() and not allow_incomplete):
                        raise IncompleteBundle("Incomplete errors in bundle. Skipping %s..." % sid)

                # Check if the submission does not already exist
                if not datastore.submission.exists(sid):
                    # Make sure bundle's submission meets minimum classification and save the submission
                    submission['classification'] = Classification.max_classification(submission['classification'],
                                                                                     min_classification)
                    submission.setdefault('metadata', {})
                    submission['metadata']['bundle.loaded'] = now_as_iso()
                    submission['metadata'].pop('replay', None)
                    submission.update(Classification.get_access_control_parts(submission['classification']))

                    if not rescan_services:
                        # Save the submission in the system
                        datastore.submission.save(sid, submission)

                    # Make sure files meet minimum classification and save the files
                    with forge.get_filestore() as filestore:
                        for f, f_data in files['infos'].items():
                            f_classification = Classification.max_classification(
                                f_data['classification'], min_classification)
                            datastore.save_or_freshen_file(f, f_data, f_data['expiry_ts'], f_classification,
                                                           cl_engine=Classification)
                            try:
                                filestore.upload(os.path.join(current_working_dir, f), f)
                            except IOError:
                                pass

                        # Make sure results meet minimum classification and save the results
                        for key, res in results['results'].items():
                            if key.endswith(".e"):
                                datastore.emptyresult.save(key, {"expiry_ts": res['expiry_ts']})
                            else:
                                res['classification'] = Classification.max_classification(
                                    res['classification'], min_classification)
                                datastore.result.save(key, res)

                        # Make sure errors meet minimum classification and save the errors
                        for ekey, err in errors['errors'].items():
                            datastore.error.save(ekey, err)

                        # Start the rescan
                        if rescan_services and SubmissionClient:
                            extracted_file_infos = {
                                k: {vk: v[vk] for vk in ['magic', 'md5', 'mime', 'sha1', 'sha256', 'size', 'type']}
                                for k, v in files['infos'].items()
                                if k in files['list']
                            }
                            with SubmissionClient(datastore=datastore, filestore=filestore,
                                                  config=config, identify=identify) as sc:
                                sc.rescan(submission, results['results'], extracted_file_infos,
                                          files['tree'], list(errors['errors'].keys()), rescan_services)
                elif not exist_ok:
                    raise SubmissionAlreadyExist("Submission %s already exists." % sid)

            # Save alert if present and does not exist
            if alert and not datastore.alert.exists(alert['alert_id']):
                alert['classification'] = Classification.max_classification(alert['classification'],
                                                                            min_classification)
                alert.setdefault('metadata', {})
                alert['metadata']['bundle.loaded'] = now_as_iso()

                alert['metadata'].pop('replay', None)
                alert['workflows_completed'] = False

                datastore.alert.save(alert['alert_id'], alert)

            return submission
        finally:
            if extracted_path != path and os.path.exists(extracted_path):
                os.remove(extracted_path)

            if cleanup and os.path.exists(path):
                os.remove(path)

            if os.path.exists(current_working_dir):
                shutil.rmtree(current_working_dir, ignore_errors=True)
