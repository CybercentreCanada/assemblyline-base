
import concurrent.futures
import json
from typing import Union, List

import elasticapm

from assemblyline.common import forge
from assemblyline.common.dict_utils import recursive_update, flatten
from assemblyline.common.isotime import now_as_iso
from assemblyline.datastore import Collection
from assemblyline.odm import Model
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
    def delete_submission_tree(self, sid, cl_engine=forge.get_classification(), cleanup=True, transport=None):
        submission = self.submission.get(sid, as_obj=False)
        errors = submission['errors']
        results = submission["results"]
        files = []
        fix_classification_files = []

        temp_files = [x[:64] for x in errors]
        temp_files.extend([x[:64] for x in results])
        temp_files = list(set(temp_files))
        for temp in temp_files:
            query = f"errors:{temp}* OR results:{temp}*"
            if self.submission.search(query, rows=0, as_obj=False)["total"] < 2:
                files.append(temp)
            else:
                fix_classification_files.append(temp)
        errors = [x for x in errors if x[:64] in files]
        results = [x for x in results if x[:64] in files]

        # Delete childs
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
                    classifications = []
                    # Find possible submissions that uses that file and the min classification for those submissions
                    for item in self.submission.stream_search(f"files.sha256:{f} OR results:{f}* OR errors:{f}*",
                                                              fl="classification,id", as_obj=False):
                        if item['id'] != sid:
                            classifications.append(item['classification'])
                    classifications = list(set(classifications))
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

                            # cur_res = self.result.get(item['id'], as_obj=False)
                            # if cur_res:
                            #     Old way
                            #     cur_res['classification'] = new_class
                            #     self.result.save(item['id'], cur_res)

                    # Alter the file classification if the new classification does not match
                    if cur_file['classification'] != new_file_class:
                        parts = cl_engine.get_access_control_parts(new_file_class)
                        update_params = [(Collection.UPDATE_SET, 'classification', new_file_class)]
                        update_params.extend([(Collection.UPDATE_SET, k, v) for k, v in parts.items()])
                        self.file.update(f, update_params)

                        # Old way
                        # cur_file['classification'] = new_file_class
                        # self.file.save(f, cur_file)

        self.submission.delete(sid)
        self.submission_tree.delete(sid)
        self.submission_summary.delete(sid)

    @elasticapm.capture_span(span_type='datastore')
    def get_all_heuristics(self):
        return {h['id']: h for h in self.ds.heuristic.stream_search("id:*", as_obj=False)}

    @elasticapm.capture_span(span_type='datastore')
    def get_multiple_results(self, keys, cl_engine=forge.get_classification(), as_obj=False):
        empties = {k: self.create_empty_result_from_key(k, cl_engine, as_obj=as_obj)
                   for k in keys if k.endswith(".e")}
        keys = [k for k in keys if not k.endswith(".e")]
        results = self.result.multiget(keys, as_dictionary=True, as_obj=as_obj)
        results.update(empties)
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
    def get_or_create_file_tree(self, submission, max_depth):
        if isinstance(submission, Model):
            submission = submission.as_primitives()

        num_files = len(list(set([x[:64] for x in submission['results']])))
        max_score = submission['max_score']

        cached_tree = self.submission_tree.get_if_exists(submission['sid'], as_obj=False)
        if cached_tree:
            tree = json.loads(cached_tree['tree'])
            if self._is_valid_tree(tree, num_files, max_score):
                return tree

        files = {}
        scores = {}
        file_hashes = [x[:64] for x in submission['results']]
        file_hashes.extend([x[:64] for x in submission['errors']])
        file_hashes.extend([f['sha256'] for f in submission['files']])
        file_data_map = self.file.multiget(list(set(file_hashes)), as_dictionary=True, as_obj=False)

        for key, item in self.result.multiget([x for x in submission['results'] if not x.endswith(".e")],
                                              as_obj=False).items():
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
                except KeyError as e:
                    missing_key = str(e).strip("'")
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

        cached_tree = {
            'expiry_ts': now_as_iso(days_until_archive * 24 * 60 * 60),
            'tree': json.dumps(tree)
        }

        self.submission_tree.save(submission['sid'], cached_tree)
        return tree

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
            "classification": cl_engine.UNRESTRICTED
        }
        done_map = {
            "heuristics": set(),
            "attack": set(),
            "tags": set()
        }

        if len(keys) == 0:
            return out

        keys = [x for x in list(keys) if not x.endswith(".e")]
        items = self.result.multiget(keys, as_obj=False)

        for key, item in items.items():
            for section in item.get('result', {}).get('sections', []):
                if user_classification:
                    if not cl_engine.is_accessible(user_classification, section['classification']):
                        continue

                out["classification"] = cl_engine.max_classification(out["classification"], section['classification'])

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
            current_fileinfo = self.ds.file.get(sha256, as_obj=False) or {}

            # Remove control fields from file info and update current file info
            for x in ['classification', 'expiry_ts', 'seen', 'archive_ts']:
                fileinfo.pop(x, None)
            current_fileinfo.update(fileinfo)

            current_fileinfo['archive_ts'] = now_as_iso(days_until_archive * 24 * 60 * 60)

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
            classification = cl_engine.min_classification(
                current_fileinfo.get('classification', classification),
                classification
            )
            current_fileinfo['classification'] = classification
            self.ds.file.save(sha256, current_fileinfo)
