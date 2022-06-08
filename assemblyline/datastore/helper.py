
import concurrent.futures
import json
import os
import time

from typing import Union, List
from datetime import datetime
from assemblyline.common.uid import get_id_from_data

import elasticapm
import elasticsearch
from assemblyline.datastore.exceptions import MultiKeyError, VersionConflictException

from assemblyline.common import forge
from assemblyline.common.dict_utils import recursive_update, flatten
from assemblyline.common.isotime import now_as_iso
from assemblyline.datastore.collection import ESCollection, log
from assemblyline.odm import Model, DATEFORMAT
from assemblyline.odm.models.alert import Alert
from assemblyline.odm.models.cached_file import CachedFile
from assemblyline.odm.models.emptyresult import EmptyResult
from assemblyline.odm.models.error import Error
from assemblyline.odm.models.file import File
from assemblyline.odm.models.filescore import FileScore
from assemblyline.odm.models.heuristic import Heuristic
from assemblyline.odm.models.result import Result
from assemblyline.odm.models.service import Service
from assemblyline.odm.models.service_delta import ServiceDelta
from assemblyline.odm.models.signature import Signature
from assemblyline.odm.models.submission import Submission
from assemblyline.odm.models.submission_summary import SubmissionSummary
from assemblyline.odm.models.submission_tree import SubmissionTree
from assemblyline.odm.models.user import User
from assemblyline.odm.models.user_favorites import UserFavorites
from assemblyline.odm.models.user_settings import UserSettings
from assemblyline.odm.models.safelist import Safelist
from assemblyline.odm.models.workflow import Workflow

config = forge.get_config()

THREAD_POOL_SIZE = int(os.environ.get("POOL_SIZE", 20))


class AssemblylineDatastore(object):
    def __init__(self, datastore_object):

        self.ds = datastore_object
        self.ds.register('alert', Alert)
        self.ds.register('cached_file', CachedFile)
        self.ds.register('emptyresult', EmptyResult)
        self.ds.register('error', Error)
        self.ds.register('file', File)
        self.ds.register('filescore', FileScore)
        self.ds.register('heuristic', Heuristic)
        self.ds.register('result', Result)
        self.ds.register('service', Service)
        self.ds.register('service_delta', ServiceDelta)
        self.ds.register('signature', Signature)
        self.ds.register('submission', Submission)
        self.ds.register('submission_tree', SubmissionTree)
        self.ds.register('submission_summary', SubmissionSummary)
        self.ds.register('user', User)
        self.ds.register('user_avatar')
        self.ds.register('user_favorites', UserFavorites)
        self.ds.register('user_settings', UserSettings)
        self.ds.register('safelist', Safelist)
        self.ds.register('workflow', Workflow)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.ds.close()

    def stop_model_validation(self):
        self.ds.validate = False

    def start_model_validation(self):
        self.ds.validate = True

    def enable_archive_access(self):
        self.ds.archive_access = True

    def disable_archive_access(self):
        self.ds.archive_access = False

    @property
    def alert(self) -> ESCollection[Alert]:
        return self.ds.alert

    @property
    def cached_file(self) -> ESCollection[CachedFile]:
        return self.ds.cached_file

    @property
    def emptyresult(self) -> ESCollection[EmptyResult]:
        return self.ds.emptyresult

    @property
    def error(self) -> ESCollection[Error]:
        return self.ds.error

    @property
    def file(self) -> ESCollection[File]:
        return self.ds.file

    @property
    def filescore(self) -> ESCollection[FileScore]:
        return self.ds.filescore

    @property
    def heuristic(self) -> ESCollection[Heuristic]:
        return self.ds.heuristic

    @property
    def result(self) -> ESCollection[Result]:
        return self.ds.result

    @property
    def service(self) -> ESCollection[Service]:
        return self.ds.service

    @property
    def service_delta(self) -> ESCollection[ServiceDelta]:
        return self.ds.service_delta

    @property
    def signature(self) -> ESCollection[Signature]:
        return self.ds.signature

    @property
    def submission(self) -> ESCollection[Submission]:
        return self.ds.submission

    @property
    def submission_summary(self) -> ESCollection[SubmissionSummary]:
        return self.ds.submission_summary

    @property
    def submission_tree(self) -> ESCollection[SubmissionTree]:
        return self.ds.submission_tree

    @property
    def user(self) -> ESCollection[User]:
        return self.ds.user

    @property
    def user_avatar(self) -> ESCollection:
        return self.ds.user_avatar

    @property
    def user_favorites(self) -> ESCollection[UserFavorites]:
        return self.ds.user_favorites

    @property
    def user_settings(self) -> ESCollection[UserSettings]:
        return self.ds.user_settings

    @property
    def vm(self) -> ESCollection:
        return self.ds.vm

    @property
    def safelist(self) -> ESCollection[Safelist]:
        return self.ds.safelist

    @property
    def workflow(self) -> ESCollection[Workflow]:
        return self.ds.workflow

    def get_collection(self, collection_name: str) -> ESCollection:
        if collection_name in self.ds.get_models():
            return getattr(self, collection_name)
        else:
            raise AttributeError(f'Collection {collection_name} does not exist.')

    @staticmethod
    def create_empty_result_from_key(key, cl_engine=forge.get_classification(), as_obj=True):
        sha256, svc_name, svc_version, _ = key.split(".", 3)
        svc_version = svc_version[1:]

        data = Result({
            "archive_ts": now_as_iso(config.datastore.ilm.days_until_archive * 24 * 60 * 60),
            "expiry_ts": now_as_iso(config.datastore.ilm.days_until_archive * 24 * 60 * 60),
            "classification": cl_engine.UNRESTRICTED,
            "response": {
                "service_name": svc_name,
                "service_version": svc_version,
            },
            "sha256": sha256
        })
        if as_obj:
            return data
        else:
            return data.as_primitives()

    @elasticapm.capture_span(span_type='datastore')
    def multi_index_bulk(self, bulk_plans):
        max_retry_backoff = 10
        retries = 0
        while True:
            try:
                plan = "\n".join([p.get_plan_data() for p in bulk_plans])
                ret_val = self.ds.client.bulk(body=plan)
                return ret_val
            except (elasticsearch.exceptions.ConnectionError,
                    elasticsearch.exceptions.ConnectionTimeout,
                    elasticsearch.exceptions.AuthenticationException):
                log.warning(f"No connection to Elasticsearch server(s): "
                            f"{' | '.join(self.ds.get_hosts(safe=True))}"
                            f", retrying...")
                time.sleep(min(retries, max_retry_backoff))
                self.ds.connection_reset()
                retries += 1

            except elasticsearch.exceptions.TransportError as e:
                err_code, msg, cause = e.args
                if err_code == 503 or err_code == '503':
                    log.warning("Looks like index is not ready yet, retrying...")
                    time.sleep(min(retries, max_retry_backoff))
                    self.ds.connection_reset()
                    retries += 1
                elif err_code == 429 or err_code == '429':
                    log.warning("Elasticsearch is too busy to perform the requested task, "
                                "we will wait a bit and retry...")
                    time.sleep(min(retries, max_retry_backoff))
                    self.ds.connection_reset()
                    retries += 1

                else:
                    raise

    @elasticapm.capture_span(span_type='datastore')
    def delete_submission_tree_bulk(self, sid, cl_engine=forge.get_classification(), cleanup=True, transport=None):
        submission = self.submission.get(sid, as_obj=False)
        if not submission:
            return

        # Create plans
        s_plan = self.submission.get_bulk_plan()
        st_plan = self.submission_tree.get_bulk_plan()
        ss_plan = self.submission_summary.get_bulk_plan()
        e_plan = self.error.get_bulk_plan()
        er_plan = self.emptyresult.get_bulk_plan()
        r_plan = self.result.get_bulk_plan()
        f_plan = self.file.get_bulk_plan()

        # Add delete operation for submission and cache
        s_plan.add_delete_operation(sid)
        for x in self.submission_tree.stream_search(f"id:{sid}*", fl="id,_index", as_obj=False):
            st_plan.add_delete_operation(x['id'], index=x['_index'])
        for x in self.submission_summary.stream_search(f"id:{sid}*", fl="id,_index", as_obj=False):
            ss_plan.add_delete_operation(x['id'], index=x['_index'])

        # Gather file list
        errors = submission['errors']
        results = submission["results"]
        files = set()
        fix_classification_files = set()
        supp_map = {}

        temp_files = [x[:64] for x in errors]
        temp_files.extend([x[:64] for x in results])
        temp_files = set(temp_files)

        # Inspect each files to see if they are reused
        for temp in temp_files:
            # Hunt for supplementary files
            supp_list = set()
            for res in self.result.stream_search(f"id:{temp}* AND response.supplementary.sha256:*",
                                                 fl="id", as_obj=False):
                if res['id'] in results:
                    result = self.result.get(res['id'], as_obj=False)
                    for supp in result['response']['supplementary']:
                        supp_list.add(supp['sha256'])

            # Check if we delete or update classification
            if self.submission.search(f"errors:{temp}* OR results:{temp}*", rows=0, as_obj=False)["total"] < 2:
                files.add(temp)
                files = files.union(supp_list)
            else:
                fix_classification_files.add(temp)
                supp_map[temp] = supp_list

        # Filter results and errors
        errors = [x for x in errors if x[:64] in files]
        results = [x for x in results if x[:64] in files]

        # Delete files, errors, results that were only used once
        for e in errors:
            e_plan.add_delete_operation(e)
        for r in results:
            if r.endswith(".e"):
                er_plan.add_delete_operation(r)
            else:
                r_plan.add_delete_operation(r)
        for f in files:
            f_plan.add_delete_operation(f)
            if transport:
                transport.delete(f)

        if fix_classification_files and cleanup:
            # Fix classification for the files that remain in the system
            for f in fix_classification_files:
                cur_file = self.file.get(f, as_obj=False)
                if cur_file:
                    # Find possible classification for the file in the system
                    query = f"NOT id:{sid} AND (files.sha256:{f} OR results:{f}* OR errors:{f}*)"
                    classifications = list(self.submission.facet('classification', query=query).keys())

                    if len(classifications) > 0:
                        new_file_class = classifications[0]
                    else:
                        new_file_class = cl_engine.UNRESTRICTED

                    for c in classifications:
                        new_file_class = cl_engine.min_classification(new_file_class, c)

                    # Find the results for that classification and alter them if the new classification does not match
                    for item in self.result.stream_search(f"id:{f}*", fl="classification,id,_index", as_obj=False):
                        new_class = cl_engine.max_classification(
                            item.get('classification', cl_engine.UNRESTRICTED), new_file_class)
                        if item.get('classification', cl_engine.UNRESTRICTED) != new_class:
                            data = cl_engine.get_access_control_parts(new_class)
                            data['classification'] = new_class
                            r_plan.add_update_operation(item['id'], data, index=item['_index'])

                    # Alter the file classification if the new classification does not match
                    if cur_file['classification'] != new_file_class:
                        data = cl_engine.get_access_control_parts(new_file_class)
                        data['classification'] = new_file_class
                        f_plan.add_update_operation(f, data)
                    # Fix associated supplementary files
                    for supp in supp_map.get(f, set()):
                        cur_supp = self.file.get(supp, as_obj=False)
                        if cur_supp:
                            if cur_supp['classification'] != new_file_class:
                                data = cl_engine.get_access_control_parts(new_file_class)
                                data['classification'] = new_file_class
                                f_plan.add_update_operation(supp, data)

        # Proceed with plan
        self.multi_index_bulk([s_plan, st_plan, ss_plan, e_plan, er_plan, r_plan, f_plan])

    @elasticapm.capture_span(span_type='datastore')
    def delete_submission_tree(self, sid, cl_engine=forge.get_classification(), cleanup=True, transport=None):
        submission = self.submission.get(sid, as_obj=False)
        if not submission:
            return

        # Gather file list
        errors = submission['errors']
        results = submission["results"]
        files = set()
        fix_classification_files = set()
        supp_map = {}

        temp_files = [x[:64] for x in errors]
        temp_files.extend([x[:64] for x in results])
        temp_files = set(temp_files)

        # Inspect each files to see if they are reused
        for temp in temp_files:
            # Hunt for supplementary files
            supp_list = set()
            for res in self.result.stream_search(f"id:{temp}* AND response.supplementary.sha256:*",
                                                 fl="id", as_obj=False):
                if res['id'] in results:
                    result = self.result.get(res['id'], as_obj=False)
                    for supp in result['response']['supplementary']:
                        supp_list.add(supp['sha256'])

            # Check if we delete or update classification
            if self.submission.search(f"errors:{temp}* OR results:{temp}*", rows=0, as_obj=False)["total"] < 2:
                files.add(temp)
                files = files.union(supp_list)
            else:
                fix_classification_files.add(temp)
                supp_map[temp] = supp_list

        # Filter results and errors
        errors = [x for x in errors if x[:64] in files]
        results = [x for x in results if x[:64] in files]

        # Delete files, errors, results that were only used once
        for e in errors:
            self.error.delete(e)
        for r in results:
            if r.endswith(".e"):
                self.emptyresult.delete(r)
            else:
                self.result.delete(r)
        for f in files:
            self.file.delete(f)
            if transport:
                transport.delete(f)

        if fix_classification_files and cleanup:
            # Fix classification for the files that remain in the system
            for f in fix_classification_files:
                cur_file = self.file.get(f, as_obj=False)
                if cur_file:
                    # Find possible classification for the file in the system
                    query = f"NOT id:{sid} AND (files.sha256:{f} OR results:{f}* OR errors:{f}*)"
                    classifications = list(self.submission.facet('classification', query=query).keys())

                    if len(classifications) > 0:
                        new_file_class = classifications[0]
                    else:
                        new_file_class = cl_engine.UNRESTRICTED

                    for c in classifications:
                        new_file_class = cl_engine.min_classification(new_file_class, c)

                    # Find the results for that classification and alter them if the new classification does not match
                    for item in self.result.stream_search(f"id:{f}*", fl="classification,id", as_obj=False):
                        new_class = cl_engine.max_classification(
                            item.get('classification', cl_engine.UNRESTRICTED), new_file_class)
                        if item.get('classification', cl_engine.UNRESTRICTED) != new_class:
                            parts = cl_engine.get_access_control_parts(new_class)
                            update_params = [(ESCollection.UPDATE_SET, 'classification', new_class)]
                            update_params.extend([(ESCollection.UPDATE_SET, k, v) for k, v in parts.items()])
                            self.result.update(item['id'], update_params)

                    # Alter the file classification if the new classification does not match
                    if cur_file['classification'] != new_file_class:
                        parts = cl_engine.get_access_control_parts(new_file_class)
                        update_params = [(ESCollection.UPDATE_SET, 'classification', new_file_class)]
                        update_params.extend([(ESCollection.UPDATE_SET, k, v) for k, v in parts.items()])
                        self.file.update(f, update_params)

                    # Fix associated supplementary files
                    for supp in supp_map.get(f, set()):
                        cur_supp = self.file.get(supp, as_obj=False)
                        if cur_supp:
                            if cur_supp['classification'] != new_file_class:
                                parts = cl_engine.get_access_control_parts(new_file_class)
                                update_params = [(ESCollection.UPDATE_SET, 'classification', new_file_class)]
                                update_params.extend([(ESCollection.UPDATE_SET, k, v) for k, v in parts.items()])
                                self.file.update(supp, update_params)

        # Delete the submission and cached trees and summaries
        self.submission.delete(sid)
        for t in [x['id'] for x in self.submission_tree.stream_search(f"id:{sid}*", fl="id", as_obj=False)]:
            self.submission_tree.delete(t)
        for s in [x['id'] for x in self.submission_summary.stream_search(f"id:{sid}*", fl="id", as_obj=False)]:
            self.submission_summary.delete(s)

    @elasticapm.capture_span(span_type='datastore')
    def get_all_heuristics(self):
        return {h['id']: h for h in self.ds.heuristic.stream_search("id:*", as_obj=False)}

    @elasticapm.capture_span(span_type='datastore')
    def get_multiple_results(self, keys, cl_engine=forge.get_classification(), as_obj=False):
        results = {k: self.create_empty_result_from_key(k, cl_engine, as_obj=as_obj)
                   for k in keys if k.endswith(".e")}
        keys = [k for k in keys if not k.endswith(".e")]
        try:
            results.update(self.result.multiget(keys, as_dictionary=True, as_obj=as_obj))
        except MultiKeyError as e:
            log.warning(f"Trying to get multiple results but some are missing: {str(e.keys)}")
            results.update(e.partial_output)
        return results

    @elasticapm.capture_span(span_type='datastore')
    def get_single_result(self, key, cl_engine=forge.get_classification(), as_obj=False):
        if key.endswith(".e"):
            data = self.create_empty_result_from_key(key, cl_engine, as_obj=as_obj)
        else:
            data = self.result.get(key, as_obj=False)

        return data

    @elasticapm.capture_span(span_type='datastore')
    def get_file_submission_meta(self, sha256, fields, access_control=None):
        query = f"files.sha256:{sha256} OR results:{sha256}*"
        with concurrent.futures.ThreadPoolExecutor(len(fields)) as executor:
            res = {field: executor.submit(self.submission.facet,
                                          field,
                                          query=query,
                                          limit=100,
                                          access_control=access_control)
                   for field in fields}

        return {k.split(".")[-1]: v.result() for k, v in res.items()}

    @elasticapm.capture_span(span_type='datastore')
    def get_file_list_from_keys(self, keys):
        # TODO: needed?
        if len(keys) == 0:
            return {}
        keys = [x for x in list(keys) if not x.endswith(".e")]
        items = self.result.multiget(keys)

        out = {}
        for key, item in items.items():
            extracted = item['response']['extracted']
            if len(extracted) == 0:
                continue
            if key[:64] not in out:
                out[key[:64]] = []
            out[key[:64]].extend(extracted)

        return out

    @elasticapm.capture_span(span_type='datastore')
    def get_file_scores_from_keys(self, keys):
        # TODO: needed?
        if len(keys) == 0:
            return {}
        keys = [x for x in list(keys) if not x.endswith(".e")]
        items = self.result.multiget(keys)

        scores = {x[:64]: 0 for x in keys}
        for key, item in items.items():
            score = item["result"]["score"]
            scores[key[:64]] += score

        return scores

    @elasticapm.capture_span(span_type='datastore')
    def get_signature_last_modified(self, sig_type=None):
        if sig_type is None:
            sig_type = "*"

        res = self.signature.search(f"type:{sig_type}", fl="last_modified",
                                    sort="last_modified desc", rows=1, as_obj=False)
        if res['total'] > 0:
            return res['items'][0]['last_modified']
        return '1970-01-01T00:00:00.000000Z'

    @elasticapm.capture_span(span_type='datastore')
    def get_or_create_file_tree(self, submission, max_depth, cl_engine=forge.get_classification(),
                                user_classification=None):
        # Generate cache key
        if user_classification is not None:
            user_classification = cl_engine.normalize_classification(user_classification, long_format=False)
            cache_key = f"{submission['sid']}_{user_classification}_supp"
            for illegal_char in [" ", ":", "/"]:
                cache_key = cache_key.replace(illegal_char, "")
        else:
            cache_key = f"{submission['sid']}_supp"

        # Transform submission into primitives
        if isinstance(submission, Model):
            submission = submission.as_primitives()

        # Get number of files and score
        num_files = len(list(set([x[:64] for x in submission['results']])))
        max_score = submission['max_score']

        # Load / Validate cache tree if exist
        cached_tree = self.submission_tree.get_if_exists(cache_key, as_obj=False)
        if cached_tree:
            tree = json.loads(cached_tree['tree'])
            if self._is_valid_tree(tree, num_files, max_score):
                log.debug(f"File tree for submission '{submission['sid']}' was loaded from cache.")
                return {
                    "tree": tree,
                    "classification": cached_tree['classification'],
                    "filtered": cached_tree['filtered'],
                    "partial": False,
                    "supplementary": json.loads(cached_tree['supplementary'])
                }

        # Set default state
        file_data_map = {}
        files = {}
        forbidden_files = set()
        max_classification = cl_engine.UNRESTRICTED
        missing_files = {}
        names = {}
        partial = submission['state'] != 'completed'
        scores = {}
        supplementary = []
        tree_cache = set()

        # Get file data
        file_hashes = [x[:64] for x in submission['results']]
        file_hashes.extend([x[:64] for x in submission['errors']])
        file_hashes.extend([f['sha256'] for f in submission['files']])
        try:
            temp_file_data_map = self.file.multiget(list(set(file_hashes)), as_dictionary=True, as_obj=False)
        except MultiKeyError as e:
            log.warning(f"Trying to generate file tree but we are missing file(s): {str(e.keys)}")
            temp_file_data_map = e.partial_output
            missing_files = set(e.keys)
            partial = True

        for key, value in temp_file_data_map.items():
            if user_classification and not cl_engine.is_accessible(user_classification, value['classification']):
                partial = True
                forbidden_files.add(key)
                continue
            file_data_map[key] = value
            max_classification = cl_engine.max_classification(max_classification, value['classification'])

        # Get result data
        try:
            results_data = self.result.multiget([x for x in submission['results'] if not x.endswith(".e")],
                                                as_obj=False)
        except MultiKeyError as e:
            log.warning(f"Trying to generate file tree but we are missing result(s): {str(e.keys)}")
            results_data = e.partial_output
            partial = True

        # Scan for extracted/supplementary files and their names
        for key, item in results_data.items():
            sha256 = key[:64]

            # Get scores
            if sha256 not in scores:
                scores[sha256] = 0
            scores[sha256] += item["result"]["score"]

            # Get files
            extracted = item['response']['extracted']

            # Get file names
            for e in extracted:
                names.setdefault(e['sha256'], set())
                names[e['sha256']].add(e['name'])

            files.setdefault(sha256, [])
            files[sha256].extend(extracted)

            # Get supplementary files
            supplementary.extend([x['sha256'] for x in item['response']['supplementary']])

        # Process a file and its children
        def process_file(current_file, tree_branch, partial, lvl=0):
            # Enforce depth protection while building the tree
            if lvl >= max_depth + 1:
                return

            # Get information about the file
            file_sha256 = current_file['sha256']
            file_name = current_file['name']

            # Check if the file not already in the tree and if its allowed to be processed
            if file_sha256 not in tree_branch \
                    and file_sha256 not in forbidden_files \
                    and file_sha256 not in missing_files:

                # Set default state for the file
                children = {}
                truncated = False

                # Load file data information if still missing
                if file_sha256 not in file_data_map:
                    file_data_map[file_sha256] = self.file.get(file_sha256, as_obj=False)

                # If file data still can't be found, bail out
                if file_sha256 not in file_data_map:
                    log.warning(f"Trying to generate file tree but we are missing a file: {file_sha256}")
                    partial = True
                    return

                # Process each children of the file
                for new_child in files.get(file_sha256, []):
                    # Check if the file has already been processed elsewhere in the tree
                    if new_child['sha256'] in tree_cache:
                        truncated = True
                    else:
                        # Process file children
                        tree_cache.add(new_child['sha256'])
                        process_file(new_child, children, partial, lvl + 1)

                # Add file and it's children to the tree
                tree_branch[file_sha256] = {
                    "name": list(names.get(file_sha256, [file_name])),
                    "type": file_data_map[file_sha256]['type'],
                    "sha256": file_data_map[file_sha256]['sha256'],
                    "size": file_data_map[file_sha256]['size'],
                    "children": children,
                    "truncated": truncated,
                    "score": scores.get(file_sha256, 0),
                }

        # Build tree
        tree = {}
        for f in submission['files']:
            tree_cache.add(f['sha256'])
            process_file(f, tree, partial)

        # Cleanup supplementary
        supplementary = list(set(supplementary))

        # Create a cache entry for the tree if it's not partial
        if not partial:
            cached_tree = {
                'expiry_ts': now_as_iso(config.datastore.ilm.days_until_archive * 24 * 60 * 60),
                'tree': json.dumps(tree),
                'classification': max_classification,
                'filtered': len(forbidden_files) > 0,
                "supplementary": json.dumps(supplementary)
            }

            self.submission_tree.save(cache_key, cached_tree)

        return {
            'tree': tree,
            'classification': max_classification,
            'filtered': len(forbidden_files) > 0,
            'partial': partial,
            "supplementary": supplementary
        }

    @staticmethod
    def _is_valid_tree(tree, num_files, max_score):
        def _count_children(sub_tree, cur_files, cur_score):
            temp_score = cur_score
            for k, v in sub_tree.items():
                if v['score'] > temp_score:
                    temp_score = v['score']
                cur_files.append(k)
                cur_files, temp_score = _count_children(v.get("children", {}), cur_files, temp_score)
            return cur_files, temp_score

        files, tree_score = _count_children(tree, [], 0)
        files = list(set(files))

        if len(files) < num_files:
            log.warning(f"Invalid cached tree, number of files is not the same: {len(files)} != {num_files}")
            return False

        if tree_score != max_score:
            log.warning(
                f"Invalid cached tree, the tree score does not match the submission score: {tree_score} != {max_score}")
            return False

        return True

    @elasticapm.capture_span(span_type='datastore')
    def get_summary_from_keys(self, keys, cl_engine=forge.get_classification(),
                              user_classification=None, keep_heuristic_sections=False):
        out = {
            "tags": [],
            "attack_matrix": [],
            "heuristics": {
                "info": [],
                "safe": [],
                "suspicious": [],
                "malicious": []
            },
            "classification": cl_engine.UNRESTRICTED,
            "filtered": False,
            "heuristic_sections": {},
            "heuristic_name_map": {}
        }
        done_map = {
            "heuristics": set(),
            "attack": set(),
            "tags": set(),
            "sections": set()
        }

        if len(keys) == 0:
            return out

        keys = [x for x in list(keys) if not x.endswith(".e")]
        file_keys = list(set([x[:64] for x in keys]))
        try:
            items = self.result.multiget(keys, as_obj=False)
        except MultiKeyError as e:
            # Generate partial summaries even if results are missing
            log.warning(f"Trying to generate summary but we are missing result(s): {str(e.keys)}")
            items = e.partial_output
            out['missing_results'] = e.keys
        try:
            files = self.file.multiget(file_keys, as_obj=False)
        except MultiKeyError as e:
            # Generate partial summaries even if results are missing
            log.warning(f"Trying to generate summary but we are missing file(s): {str(e.keys)}")
            files = e.partial_output
            out['missing_files'] = e.keys

        for key, item in items.items():
            sorted_sections = sorted(item.get('result', {}).get('sections', []),
                                     key=lambda i: i['heuristic']['score'] if i['heuristic'] is not None else 0,
                                     reverse=True)
            for section in sorted_sections:
                file_classification = files.get(key[:64], {}).get('classification', section['classification'])
                if user_classification:
                    if not cl_engine.is_accessible(user_classification, section['classification']):
                        out["filtered"] = True
                        continue
                    if not cl_engine.is_accessible(user_classification, file_classification):
                        out["filtered"] = True
                        continue

                out["classification"] = cl_engine.max_classification(out["classification"], section['classification'])
                out["classification"] = cl_engine.max_classification(out["classification"], file_classification)

                h_type = "info"

                if section.get('heuristic', False):
                    heur_id = section['heuristic']['heur_id']
                    heur_name = section['heuristic']['name']

                    # Get the heuristics data
                    if section['heuristic']['score'] < 0:
                        h_type = "safe"
                    elif section['heuristic']['score'] < 300:
                        h_type = "info"
                    elif section['heuristic']['score'] < 1000:
                        h_type = "suspicious"
                    else:
                        h_type = "malicious"

                    cache_key = f"{heur_id}_{key}"
                    if cache_key not in done_map['heuristics']:
                        out['heuristics'][h_type].append({
                            'heur_id': heur_id,
                            'name': heur_name,
                            'key': key
                        })
                        done_map['heuristics'].add(cache_key)

                    if keep_heuristic_sections:
                        # Set defaults
                        out['heuristic_sections'].setdefault(heur_id, [])
                        out['heuristic_name_map'].setdefault(heur_name, [])

                        # Set Name map
                        if heur_id not in out['heuristic_name_map'][heur_name]:
                            out['heuristic_name_map'][heur_name].append(heur_id)

                        # Insert unique sections
                        section_key = get_id_from_data(f"{heur_id}_{section['title_text']}_{section['body']}_{h_type}")
                        if section_key not in done_map['sections']:
                            out['heuristic_sections'][heur_id].append(section)
                            done_map['sections'].add(section_key)

                    for attack in section['heuristic'].get('attack', []):
                        # Get attack matrix data
                        attack_id = attack['attack_id']

                        cache_key = f"{attack_id}_{key}"
                        if cache_key not in done_map['attack']:
                            out['attack_matrix'].append({
                                "key": key,
                                "attack_id": attack_id,
                                "h_type": h_type,
                                "name": attack['pattern'],
                                "categories": attack['categories']
                            })
                            done_map['attack'].add(cache_key)

                # Get tagging data
                for tag_type, tags in flatten(section.get('tags', {})).items():
                    if tags is not None:
                        for tag in tags:
                            cache_key = f"{tag_type}_{tag}_{key}"

                            if cache_key not in done_map['tags']:
                                out['tags'].append({
                                    'type': tag_type,
                                    'h_type': h_type,
                                    'short_type': tag_type.rsplit(".", 1)[-1],
                                    'value': tag,
                                    'key': key,
                                    'safelisted': False
                                })
                                done_map['tags'].add(cache_key)

                # Get safelisted tag data
                for tag_type, tags in section.get('safelisted_tags', {}).items():
                    if tags is not None:
                        for tag in tags:
                            cache_key = f"{tag_type}_{tag}_{key}"

                            if cache_key not in done_map['tags']:
                                out['tags'].append({
                                    'type': tag_type,
                                    'h_type': h_type,
                                    'short_type': tag_type.rsplit(".", 1)[-1],
                                    'value': tag,
                                    'key': key,
                                    'safelisted': True
                                })
                                done_map['tags'].add(cache_key)

        return out

    @elasticapm.capture_span(span_type='datastore')
    def get_tag_list_from_keys(self, keys):
        if len(keys) == 0:
            return []
        keys = [x for x in list(keys) if not x.endswith(".e")]
        items = self.result.multiget(keys, as_obj=False)

        out = []
        for key, item in items.items():
            for section in item.get('result', {}).get('sections', []):
                for tag_type, tags in flatten(section.get('tags', {})).items():
                    if tags is not None:
                        for tag in tags:
                            out.append({
                                'type': tag_type,
                                'short_type': tag_type.rsplit(".", 1)[-1],
                                'value': tag,
                                'key': key,
                                'safelisted': False
                            })
                for tag_type, tags in section.get('safelisted_tags', {}).items():
                    if tags is not None:
                        for tag in tags:
                            out.append({
                                'type': tag_type,
                                'short_type': tag_type.rsplit(".", 1)[-1],
                                'value': tag,
                                'key': key,
                                'safelisted': True
                            })

        return out

    @elasticapm.capture_span(span_type='datastore')
    def get_attack_matrix_from_keys(self, keys):
        if len(keys) == 0:
            return []
        keys = [x for x in list(keys) if not x.endswith(".e")]
        items = self.result.multiget(keys, as_obj=False)

        out = []
        for key, item in items.items():
            for section in item.get('result', {}).get('sections', []):
                attack_id = section.get('heuristic', {}).get('attack_id', None)
                if attack_id:
                    out.append({
                        "key": key,
                        "attack_id": attack_id,
                        "name": section['heuristic']['attack_pattern'],
                        "categories": section['heuristic']['attack_categories']
                    })

        return out

    @elasticapm.capture_span(span_type='datastore')
    def get_service_with_delta(self, service_name, version=None, as_obj=True) -> Union[Service, dict, None]:
        svc = self.ds.service_delta.get(service_name)
        if svc is None:
            return None

        if version is not None:
            svc.version = version

        svc_version_data = self.ds.service.get(f"{service_name}_{svc.version}")
        if svc_version_data is None:
            return None

        svc_version_data = recursive_update(svc_version_data.as_primitives(strip_null=True),
                                            svc.as_primitives(strip_null=True),
                                            stop_keys=['config'])
        if as_obj:
            return Service(svc_version_data)
        else:
            return svc_version_data

    @elasticapm.capture_span(span_type='datastore')
    def get_stat_for_heuristic(self, p_id):
        log.info(f"Generating stats for heuristic: {p_id})")
        query = f"result.sections.heuristic.heur_id:{p_id}"
        stats = self.ds.result.stats("result.score", query=query)

        if stats['count'] == 0:
            up_stats = {'count': 0, 'min': 0, 'max': 0, 'avg': 0, 'sum': 0, 'first_hit': None, 'last_hit': None}
        else:
            first = self.ds.result.search(query=query, fl='created', rows=1,
                                          sort="created asc", as_obj=False, use_archive=True)['items'][0]['created']
            last = self.ds.result.search(query=query, fl='created', rows=1,
                                         sort="created desc", as_obj=False, use_archive=True)['items'][0]['created']
            up_stats = {
                'count': stats['count'],
                'min': int(stats['min']),
                'max': int(stats['max']),
                'avg': int(stats['avg']),
                'sum': int(stats['sum']),
                'first_hit': first,
                'last_hit': last
            }

            self.ds.heuristic.update(p_id, [
                (self.ds.heuristic.UPDATE_SET, 'stats', up_stats)
            ])

        return up_stats

    @elasticapm.capture_span(span_type='datastore')
    def calculate_heuristic_stats(self):
        # Calculate stats for all heuristics
        heuristics = [x['heur_id'] for x in self.ds.heuristic.stream_search("heur_id:*", fl="heur_id", as_obj=False)]

        log.info(f"All {len(heuristics)} heuristics will have their statistics updated.")

        # Update all heuristics found
        with concurrent.futures.ThreadPoolExecutor(max(min(len(heuristics), THREAD_POOL_SIZE), 1)) as executor:
            for heur_id in heuristics:
                executor.submit(self.get_stat_for_heuristic, heur_id)

    @elasticapm.capture_span(span_type='datastore')
    def get_stat_for_signature(self, p_id, p_source, p_name, p_type):
        if p_id is None:
            log.info(f"Finding ID for {p_type.upper()} signature: \"{p_name}\" [{p_source}]")
            try:
                res = self.signature.search(f"type:\"{p_type}\" AND source:\"{p_source}\" AND name:\"{p_name}\"",
                                            fl="id", as_obj=False)['items']
                for item in res:
                    p_id = item['id']
            except Exception:
                pass

        if not p_id:
            log.error(f"Failed to find ID for {p_type.upper()} signature: \"{p_name}\" [{p_source}]")
            return None

        log.info(f"Generating stats for {p_type.upper()} signature: {p_id}")

        query = f'result.sections.tags.file.rule.{p_type}:"{p_source}.{p_name}"'
        stats = self.ds.result.stats("result.score", query=query)
        if stats['count'] == 0:
            up_stats = {'count': 0, 'min': 0, 'max': 0, 'avg': 0, 'sum': 0, 'first_hit': None, 'last_hit': None}
        else:
            first = self.ds.result.search(query=query, fl='created', rows=1,
                                          sort="created asc", as_obj=False, use_archive=True)['items'][0]['created']
            last = self.ds.result.search(query=query, fl='created', rows=1,
                                         sort="created desc", as_obj=False, use_archive=True)['items'][0]['created']
            up_stats = {
                'count': stats['count'],
                'min': int(stats['min']),
                'max': int(stats['max']),
                'avg': int(stats['avg']),
                'sum': int(stats['sum']),
                'first_hit': first,
                'last_hit': last
            }

            self.ds.signature.update(p_id, [
                (self.ds.signature.UPDATE_SET, 'stats', up_stats)
            ])

        return up_stats

    @elasticapm.capture_span(span_type='datastore')
    def calculate_signature_stats(self, lookback_time="now-1d"):
        # Compute updated signatures since lookback time
        signatures = set()
        query = f"result.sections.tags.file.rule.\\*:* AND created:{{{lookback_time} TO now]"
        fl = "created,result.sections.tags.file.rule.*"

        new_time = None
        for res in self.ds.result.stream_search(query, fl=fl, as_obj=False):
            for sec in res['result']['sections']:
                for rule_type, rules in sec['tags']['file']['rule'].items():
                    for rule in rules:
                        try:
                            source, name = rule.split('.', 1)
                            signatures.add((source, name, rule_type))
                        except Exception:
                            log.warning(f'Failed to parse rule name for rule: {rule} [{rule_type}]')

            if new_time is None or res['created'] > new_time:
                new_time = res['created']

        log.info(f"{len(signatures)} signatures where triggered since: {lookback_time}.")

        # Bail out if no signatures
        if not signatures:
            return lookback_time

        # Update all signatures found
        with concurrent.futures.ThreadPoolExecutor(max(min(len(signatures), THREAD_POOL_SIZE), 1)) as executor:
            for source, name, sig_type in signatures:
                executor.submit(self.get_stat_for_signature, None, source, name, sig_type)

        return new_time

    @elasticapm.capture_span(span_type='datastore')
    def list_all_services(self, as_obj=True, full=False) -> Union[List[dict], List[Service]]:
        """
        :param as_obj: Return ODM objects rather than dicts
        :param full: If true retrieve all the fields of the service object, otherwise only
                     fields returned by search are given.
        """
        mask = None if full else list(self.ds.service.stored_fields.keys())

        # List all services from service delta (Return all fields if full is true)
        service_delta = list(self.ds.service_delta.stream_search("id:*", fl="*" if full else None))

        # Gather all matching services and apply a mask if we don't want the full source object
        service_data = [Service(s, mask=mask)
                        for s in self.ds.service.multiget([f"{item.id}_{item.version}" for item in service_delta],
                                                          as_obj=False, as_dictionary=False)]

        # Recursively update the service data with the service delta while stripping nulls
        services = [recursive_update(data.as_primitives(strip_null=True), delta.as_primitives(strip_null=True),
                                     stop_keys=['config'])
                    for data, delta in zip(service_data, service_delta)]

        # Return as an objet if needs be...
        if as_obj:
            return [Service(s, mask=mask) for s in services]
        else:
            return services

    @elasticapm.capture_span(span_type='datastore')
    def list_all_heuristics(self, as_obj=True) -> Union[List[dict], List[Heuristic]]:
        """
        :param as_obj: Return ODM objects rather than dicts
        """
        heuristics = list(self.ds.heuristic.stream_search("id:*", as_obj=as_obj))
        return heuristics

    @elasticapm.capture_span(span_type='datastore')
    def save_or_freshen_file(self, sha256, fileinfo, expiry, classification,
                             cl_engine=forge.get_classification(), redis=None, is_section_image=False):
        # Remove control fields from new file info
        for x in ['classification', 'expiry_ts', 'seen', 'archive_ts']:
            fileinfo.pop(x, None)
        # Clean up and prepare timestamps
        if isinstance(expiry, datetime):
            expiry = expiry.strftime(DATEFORMAT)
        archive_time = now_as_iso(config.datastore.ilm.days_until_archive * 24 * 60 * 60)

        while True:
            current_fileinfo, version = self.ds.file.get_if_exists(
                sha256, as_obj=False, archive_access=config.datastore.ilm.update_archive, version=True)

            if current_fileinfo is None:
                current_fileinfo = {}
            else:
                # If the freshen we are doing won't change classification, we can do it via an update operation
                classification = cl_engine.min_classification(
                    str(current_fileinfo.get('classification', classification)),
                    str(classification)
                )
                if classification == current_fileinfo.get('classification', None):
                    operations = [
                        (self.ds.file.UPDATE_SET, key, value)
                        for key, value in fileinfo.items()
                    ]
                    operations.extend([
                        (self.ds.file.UPDATE_MAX, 'archive_ts', archive_time),
                        (self.ds.file.UPDATE_INC, 'seen.count', 1),
                        (self.ds.file.UPDATE_MAX, 'seen.last', now_as_iso()),
                    ])
                    if expiry:
                        operations.append((self.ds.file.UPDATE_MAX, 'expiry_ts', expiry))
                    if self.ds.file.update(sha256, operations):
                        return

            # Add new fileinfo to current from database
            current_fileinfo.update(fileinfo)
            current_fileinfo['archive_ts'] = archive_time

            # Update expiry time
            current_expiry = current_fileinfo.get('expiry_ts', expiry)
            if current_expiry and expiry:
                current_fileinfo['expiry_ts'] = max(current_expiry, expiry)
            else:
                current_fileinfo['expiry_ts'] = None

            # Update seen counters
            now = now_as_iso()
            current_fileinfo['seen'] = seen = current_fileinfo.get('seen', {})
            seen['count'] = seen.get('count', 0) + 1
            seen['last'] = now
            seen['first'] = seen.get('first', now)

            # Update Classification
            current_fileinfo['classification'] = classification

            # Update section image status
            current_fileinfo['is_section_image'] = current_fileinfo.get('is_section_image', False) or is_section_image

            try:
                self.ds.file.save(sha256, current_fileinfo, version=version)
                return
            except VersionConflictException as vce:
                log.info(f"Retrying save or freshen due to version conflict: {str(vce)}")
