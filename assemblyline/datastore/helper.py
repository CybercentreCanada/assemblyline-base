
import concurrent.futures
import json
import time

from typing import Union, List
from datetime import datetime

import elasticapm
import elasticsearch
from assemblyline.datastore.exceptions import MultiKeyError

from assemblyline.common import forge
from assemblyline.common.dict_utils import recursive_update, flatten
from assemblyline.common.isotime import now_as_iso
from assemblyline.datastore import Collection, log
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
from assemblyline.odm.models.workflow import Workflow
from assemblyline.remote.datatypes.lock import Lock

days_until_archive = forge.get_config().datastore.ilm.days_until_archive


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
        self.ds.register('workflow', Workflow)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.ds.close()

    def enable_archive_access(self):
        self.ds.archive_access = True

    def disable_archive_access(self):
        self.ds.archive_access = False

    @property
    def alert(self) -> Collection:
        return self.ds.alert

    @property
    def cached_file(self) -> Collection:
        return self.ds.cached_file

    @property
    def emptyresult(self) -> Collection:
        return self.ds.emptyresult

    @property
    def error(self) -> Collection:
        return self.ds.error

    @property
    def file(self) -> Collection:
        return self.ds.file

    @property
    def filescore(self) -> Collection:
        return self.ds.filescore

    @property
    def heuristic(self) -> Collection:
        return self.ds.heuristic

    @property
    def result(self) -> Collection:
        return self.ds.result

    @property
    def service(self) -> Collection:
        return self.ds.service

    @property
    def service_client(self) -> Collection:
        return self.ds.service_client

    @property
    def service_delta(self) -> Collection:
        return self.ds.service_delta

    @property
    def signature(self) -> Collection:
        return self.ds.signature

    @property
    def submission(self) -> Collection:
        return self.ds.submission

    @property
    def submission_summary(self) -> Collection:
        return self.ds.submission_summary

    @property
    def submission_tree(self) -> Collection:
        return self.ds.submission_tree

    @property
    def user(self) -> Collection:
        return self.ds.user

    @property
    def user_avatar(self) -> Collection:
        return self.ds.user_avatar

    @property
    def user_favorites(self) -> Collection:
        return self.ds.user_favorites

    @property
    def user_settings(self) -> Collection:
        return self.ds.user_settings

    @property
    def vm(self) -> Collection:
        return self.ds.vm

    @property
    def workflow(self) -> Collection:
        return self.ds.workflow

    def get_collection(self, collection_name):
        if collection_name in self.ds.get_models():
            return getattr(self, collection_name)
        else:
            raise AttributeError(f'Collection {collection_name} does not exist.')

    @staticmethod
    def create_empty_result_from_key(key, cl_engine=forge.get_classification(), as_obj=True):
        sha256, svc_name, svc_version, _ = key.split(".", 3)
        svc_version = svc_version[1:]

        data = Result({
            "archive_ts": now_as_iso(days_until_archive * 24 * 60 * 60),
            "expiry_ts": now_as_iso(days_until_archive * 24 * 60 * 60),
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
                            update_params = [(Collection.UPDATE_SET, 'classification', new_class)]
                            update_params.extend([(Collection.UPDATE_SET, k, v) for k, v in parts.items()])
                            self.result.update(item['id'], update_params)

                    # Alter the file classification if the new classification does not match
                    if cur_file['classification'] != new_file_class:
                        parts = cl_engine.get_access_control_parts(new_file_class)
                        update_params = [(Collection.UPDATE_SET, 'classification', new_file_class)]
                        update_params.extend([(Collection.UPDATE_SET, k, v) for k, v in parts.items()])
                        self.file.update(f, update_params)

                    # Fix associated supplementary files
                    for supp in supp_map.get(f, set()):
                        cur_supp = self.file.get(supp, as_obj=False)
                        if cur_supp:
                            if cur_supp['classification'] != new_file_class:
                                parts = cl_engine.get_access_control_parts(new_file_class)
                                update_params = [(Collection.UPDATE_SET, 'classification', new_file_class)]
                                update_params.extend([(Collection.UPDATE_SET, k, v) for k, v in parts.items()])
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
        if user_classification is not None:
            user_classification = cl_engine.normalize_classification(user_classification, long_format=False)
            cache_key = f"{submission['sid']}_{user_classification}"
            for illegal_char in [" ", ":", "/"]:
                cache_key = cache_key.replace(illegal_char, "")
        else:
            cache_key = submission['sid']

        if isinstance(submission, Model):
            submission = submission.as_primitives()

        num_files = len(list(set([x[:64] for x in submission['results']])))
        max_score = submission['max_score']

        cached_tree = self.submission_tree.get_if_exists(cache_key, as_obj=False)
        if cached_tree:
            tree = json.loads(cached_tree['tree'])
            if self._is_valid_tree(tree, num_files, max_score):
                return {
                    "tree": tree,
                    "classification": cached_tree['classification'],
                    "filtered": cached_tree['filtered'],
                    "partial": False
                }

        partial = False
        files = {}
        scores = {}
        missing_files = []
        file_hashes = [x[:64] for x in submission['results']]
        file_hashes.extend([x[:64] for x in submission['errors']])
        file_hashes.extend([f['sha256'] for f in submission['files']])
        try:
            temp_file_data_map = self.file.multiget(list(set(file_hashes)), as_dictionary=True, as_obj=False)
        except MultiKeyError as e:
            log.warning(f"Trying to generate file tree but we are missing file(s): {str(e.keys)}")
            temp_file_data_map = e.partial_output
            missing_files = e.keys
            partial = True
        forbidden_files = set()

        max_classification = cl_engine.UNRESTRICTED
        file_data_map = {}
        for key, value in temp_file_data_map.items():
            if user_classification and not cl_engine.is_accessible(user_classification, value['classification']):
                forbidden_files.add(key)
                continue
            file_data_map[key] = value
            max_classification = cl_engine.max_classification(max_classification, value['classification'])

        try:
            results_data = self.result.multiget([x for x in submission['results'] if not x.endswith(".e")],
                                                as_obj=False)
        except MultiKeyError as e:
            log.warning(f"Trying to generate file tree but we are missing result(s): {str(e.keys)}")
            results_data = e.partial_output
            partial = True

        for key, item in results_data.items():
            sha256 = key[:64]

            # Get scores
            if sha256 not in scores:
                scores[sha256] = 0
            scores[sha256] += item["result"]["score"]

            # Get files
            extracted = item['response']['extracted']
            if len(extracted) == 0:
                continue
            if sha256 not in files:
                files[sha256] = []
            files[sha256].extend(extracted)

        tree_cache = []

        def recurse_tree(child_p, placeholder, parents_p, lvl=0):
            if lvl == max_depth + 1:
                # Enforce depth protection while building the tree
                return

            if child_p['sha256'] in placeholder:
                placeholder[child_p['sha256']]['name'].append(child_p['name'])
            else:
                children_list = {}
                truncated = False
                child_list = files.get(child_p['sha256'], [])
                for new_child in child_list:
                    if new_child['sha256'] in tree_cache:
                        truncated = True
                        continue
                    tree_cache.append(child['sha256'])

                    if new_child['sha256'] not in parents_p:
                        recurse_tree(new_child, children_list,
                                     parents_p + [child_p['sha256']], lvl + 1)

                try:
                    placeholder[child_p['sha256']] = {
                        "name": [child_p['name']],
                        "type": file_data_map[child_p['sha256']]['type'],
                        "sha256": file_data_map[child_p['sha256']]['sha256'],
                        "size": file_data_map[child_p['sha256']]['size'],
                        "children": children_list,
                        "truncated": truncated,
                        "score": scores.get(child_p['sha256'], 0),
                    }
                except KeyError as ke:
                    missing_key = str(ke).strip("'")
                    if missing_key not in forbidden_files and missing_key not in missing_files:
                        file_data_map[missing_key] = self.file.get(missing_key, as_obj=False)
                        placeholder[child_p['sha256']] = {
                            "name": [child_p['name']],
                            "type": file_data_map[child_p['sha256']]['type'],
                            "sha256": file_data_map[child_p['sha256']]['sha256'],
                            "size": file_data_map[child_p['sha256']]['size'],
                            "children": children_list,
                            "truncated": truncated,
                            "score": scores.get(child_p['sha256'], 0),
                        }

        tree = {}
        for f in submission['files']:
            sha256 = f['sha256']
            name = f['name']

            if sha256 in tree:
                tree[sha256]['name'].append(name)
            else:
                parents = [sha256]
                children = {}
                c_list = files.get(sha256, [])
                for child in c_list:
                    tree_cache.append(child['sha256'])
                    recurse_tree(child, children, parents)

                tree[sha256] = {
                    "name": [name],
                    "children": children,
                    "type": file_data_map[sha256]['type'],
                    "sha256": file_data_map[sha256]['sha256'],
                    "size": file_data_map[sha256]['size'],
                    "truncated": False,
                    "score": scores.get(sha256, 0),
                }

        if not partial:
            cached_tree = {
                'expiry_ts': now_as_iso(days_until_archive * 24 * 60 * 60),
                'tree': json.dumps(tree),
                'classification': max_classification,
                'filtered': len(forbidden_files) > 0
            }

            self.submission_tree.save(cache_key, cached_tree)

        return {
            'tree': tree,
            'classification': max_classification,
            'filtered': len(forbidden_files) > 0,
            'partial': partial
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
            return False

        if tree_score != max_score:
            return False

        return True

    @elasticapm.capture_span(span_type='datastore')
    def get_summary_from_keys(self, keys, cl_engine=forge.get_classification(), user_classification=None):
        out = {
            "tags": [],
            "attack_matrix": [],
            "heuristics": {
                "info": [],
                "suspicious": [],
                "malicious": []
            },
            "classification": cl_engine.UNRESTRICTED,
            "filtered": False
        }
        done_map = {
            "heuristics": set(),
            "attack": set(),
            "tags": set()
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
            for section in item.get('result', {}).get('sections', []):
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
                    # Get the heuristics data
                    if section['heuristic']['score'] < 100:
                        h_type = "info"
                    elif section['heuristic']['score'] < 1000:
                        h_type = "suspicious"
                    else:
                        h_type = "malicious"

                    cache_key = f"{section['heuristic']['heur_id']}_{key}"
                    if cache_key not in done_map['heuristics']:
                        out['heuristics'][h_type].append({
                            'heur_id': section['heuristic']['heur_id'],
                            'name': section['heuristic']['name'],
                            'key': key
                        })
                        done_map['heuristics'].add(cache_key)

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
                                    'key': key
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
                                'key': key
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
    def get_service_with_delta(self, service_name, version=None, as_obj=True):
        svc = self.ds.service_delta.get(service_name)
        if svc is None:
            return svc

        if version is not None:
            svc.version = version

        svc_version_data = self.ds.service.get(f"{service_name}_{svc.version}")
        if svc_version_data is None:
            return svc_version_data

        svc_version_data = recursive_update(svc_version_data.as_primitives(strip_null=True),
                                            svc.as_primitives(strip_null=True))
        if as_obj:
            return Service(svc_version_data)
        else:
            return svc_version_data

    @elasticapm.capture_span(span_type='datastore')
    def get_stat_for_heuristic(self, p_id):
        query = f"result.sections.heuristic.heur_id:{p_id}"
        stats = self.ds.result.stats("result.score", query=query)

        if stats['count'] == 0:
            up_stats = {'count': 0, 'min': 0, 'max': 0, 'avg': 0, 'sum': 0}
        else:
            first = self.ds.result.search(query=query, fl='created', rows=1,
                                          sort="created asc", as_obj=False)['items'][0]['created']
            last = self.ds.result.search(query=query, fl='created', rows=1,
                                         sort="created desc", as_obj=False)['items'][0]['created']
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
        heur_list = sorted([(x['heur_id'])
                            for x in self.ds.heuristic.stream_search("heur_id:*", fl="heur_id,name,classification",
                                                                     as_obj=False)])

        with concurrent.futures.ThreadPoolExecutor(max(min(len(heur_list), 20), 1)) as executor:
            for heur_id in heur_list:
                executor.submit(self.get_stat_for_heuristic, heur_id)

    @elasticapm.capture_span(span_type='datastore')
    def get_stat_for_signature(self, p_id, p_source, p_name, p_type):
        query = f'result.sections.tags.file.rule.{p_type}:"{p_source}.{p_name}"'
        stats = self.ds.result.stats("result.score", query=query)
        if stats['count'] == 0:
            up_stats = {'count': 0, 'min': 0, 'max': 0, 'avg': 0, 'sum': 0}
        else:
            first = self.ds.result.search(query=query, fl='created', rows=1,
                                          sort="created asc", as_obj=False)['items'][0]['created']
            last = self.ds.result.search(query=query, fl='created', rows=1,
                                         sort="created desc", as_obj=False)['items'][0]['created']
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
    def calculate_signature_stats(self):
        sig_list = sorted([(x['id'], x['source'], x['name'], x['type'])
                           for x in self.ds.signature.stream_search("id:*",
                                                                    fl="id,name,type,source,classification",
                                                                    as_obj=False)])

        with concurrent.futures.ThreadPoolExecutor(max(min(len(sig_list), 20), 1)) as executor:
            for sid, source, name, sig_type in sig_list:
                executor.submit(self.get_stat_for_signature, sid, source, name, sig_type)

    @elasticapm.capture_span(span_type='datastore')
    def list_all_services(self, as_obj=True, full=False) -> Union[List[dict], List[Service]]:
        """
        :param as_obj: Return ODM objects rather than dicts
        :param full: If true retrieve all the fields of the service object, otherwise only
                     fields returned by search are given.
        """
        items = list(self.ds.service_delta.stream_search("id:*", as_obj=False))

        if full:
            service_data = self.ds.service.multiget([f"{item['id']}_{item['version']}" for item in items],
                                                    as_dictionary=False)
            service_delta = self.ds.service_delta.multiget([item['id'] for item in items], as_dictionary=False)
            services = [recursive_update(data.as_primitives(strip_null=True), delta.as_primitives(strip_null=True))
                        for data, delta in zip(service_data, service_delta)]

        else:
            services_versions = {item['id']: item for item in self.ds.service.stream_search("id:*", as_obj=False)}
            services = [recursive_update(services_versions[f"{item['id']}_{item['version']}"], item)
                        for item in items if f"{item['id']}_{item['version']}" in services_versions]

        if as_obj:
            mask = None
            if not full and services:
                mask = services[0].keys()
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
                             cl_engine=forge.get_classification(), redis=None):
        with Lock(f'save-or-freshen-file-{sha256}', 5, host=redis):
            current_fileinfo = self.ds.file.get(sha256, as_obj=False, force_archive_access=True) or {}

            # Remove control fields from file info and update current file info
            for x in ['classification', 'expiry_ts', 'seen', 'archive_ts']:
                fileinfo.pop(x, None)
            current_fileinfo.update(fileinfo)

            current_fileinfo['archive_ts'] = now_as_iso(days_until_archive * 24 * 60 * 60)

            # Update expiry time
            if isinstance(expiry, datetime):
                expiry = expiry.strftime(DATEFORMAT)
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
            classification = cl_engine.min_classification(
                str(current_fileinfo.get('classification', classification)),
                str(classification)
            )
            current_fileinfo['classification'] = classification
            self.ds.file.save(sha256, current_fileinfo, force_archive_access=True)
