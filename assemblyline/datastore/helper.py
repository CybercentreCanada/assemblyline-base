
import concurrent.futures
import json

from assemblyline.common import forge
from assemblyline.common.isotime import now_as_iso
from assemblyline.datastore import Collection
from assemblyline.odm import Model
from assemblyline.odm.models.alert import Alert
from assemblyline.odm.models.cached_file import CachedFile
from assemblyline.odm.models.emptyresult import EmptyResult
from assemblyline.odm.models.error import Error
from assemblyline.odm.models.file import File
from assemblyline.odm.models.filescore import FileScore
from assemblyline.odm.models.result import Result
from assemblyline.odm.models.service import Service
from assemblyline.odm.models.signature import Signature
from assemblyline.odm.models.submission import Submission
from assemblyline.odm.models.submission_tags import SubmissionTags
from assemblyline.odm.models.submission_tree import SubmissionTree
from assemblyline.odm.models.tc_signature import TCSignature
from assemblyline.odm.models.user import User
from assemblyline.odm.models.user_favorites import UserFavorites
from assemblyline.odm.models.user_settings import UserSettings
from assemblyline.odm.models.vm import VM
from assemblyline.odm.models.workflow import Workflow
from assemblyline.remote.datatypes.lock import Lock


class AssemblylineDatastore(object):
    def __init__(self, datastore_object):
        self.ds = datastore_object
        self.ds.register('alert', Alert)
        self.ds.register('cached_file', CachedFile)
        self.ds.register('emptyresult', EmptyResult)
        self.ds.register('error', Error)
        self.ds.register('file', File)
        self.ds.register('filescore', FileScore)
        self.ds.register('result', Result)
        self.ds.register('service', Service)
        self.ds.register('signature', Signature)
        self.ds.register('submission', Submission)
        self.ds.register('submission_tree', SubmissionTree)
        self.ds.register('submission_tags', SubmissionTags)
        self.ds.register('tc_signature', TCSignature)
        self.ds.register('user', User)
        self.ds.register('user_avatar')
        self.ds.register('user_favorites', UserFavorites)
        self.ds.register('user_settings', UserSettings)
        self.ds.register('vm', VM)
        self.ds.register('workflow', Workflow)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.ds.close()

    @property
    def alert(self):
        return self.ds.alert

    @property
    def cached_file(self):
        return self.ds.cached_file

    @property
    def emptyresult(self):
        return self.ds.emptyresult

    @property
    def error(self):
        return self.ds.error

    @property
    def file(self):
        return self.ds.file

    @property
    def filescore(self):
        return self.ds.filescore

    @property
    def result(self):
        return self.ds.result

    @property
    def service(self):
        return self.ds.service

    @property
    def signature(self):
        return self.ds.signature

    @property
    def submission(self):
        return self.ds.submission

    @property
    def submission_tags(self):
        return self.ds.submission_tags

    @property
    def submission_tree(self):
        return self.ds.submission_tree

    @property
    def tc_signature(self):
        return self.ds.tc_signature

    @property
    def user(self):
        return self.ds.user

    @property
    def user_avatar(self):
        return self.ds.user_avatar

    @property
    def user_favorites(self):
        return self.ds.user_favorites

    @property
    def user_settings(self):
        return self.ds.user_settings

    @property
    def vm(self):
        return self.ds.vm

    @property
    def workflow(self):
        return self.ds.workflow

    @staticmethod
    def create_empty_result_from_key(key, cl_engine=forge.get_classification(), as_obj=True):
        sha256, svc_name, svc_version, _ = key.split(".", 3)
        svc_version = svc_version[1:]

        data = Result({
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
        self.submission_tags.delete(sid)

    def get_multiple_results(self, keys, cl_engine=forge.get_classification(), as_obj=False):
        empties = {k: self.create_empty_result_from_key(k, cl_engine, as_obj=as_obj)
                   for k in keys if k.endswith(".e")}
        keys = [k for k in keys if not k.endswith(".e")]
        results = self.result.multiget(keys, as_dictionary=True, as_obj=as_obj)
        results.update(empties)
        return results

    def get_single_result(self, key, cl_engine=forge.get_classification(), as_obj=False):
        if key.endswith(".e"):
            data = self.create_empty_result_from_key(key, cl_engine, as_obj=as_obj)
        else:
            data = self.result.get(key, as_obj=False)

        return data

    def get_file_submission_meta(self, sha256, fields, access_control=None):
        query = f"files.sha256:{sha256} OR results:{sha256}*"
        with concurrent.futures.ThreadPoolExecutor(len(fields)) as executor:
            res = {field: executor.submit(self.submission.facet,
                                          field,
                                          query=query,
                                          limit=100,
                                          access_control=access_control)
                   for field in fields}

        return {k: v.result() for k, v in res.items()}

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

    def get_signature_last_modified(self):
        res = self.signature.search("id:*", fl="meta.last_modified",
                                    sort="meta.last_modified desc", rows=1, as_obj=False)
        if res['total'] > 0:
            return res['items'][0]['meta']['last_modified']
        return '1970-01-01T00:00:00.000000Z'

    def get_signature_next_revision_for_name(self, org, name):
        query = "meta.rule_id:%s_* AND name:%s" % (org, name)
        results = self.signature.search(query, offset=0, rows=1, sort="id desc", as_obj=False)["items"]
        if len(results) == 0:
            return None, None
        else:
            try:
                return results[0]["meta"]["rule_id"], int(results[0]["meta.rule_version"]) + 1
            except (ValueError, KeyError):
                return None, None

    def get_signature_last_id(self, org):
        query = "meta.rule_id:%s_0*" % org
        results = self.signature.search(query, offset=0, rows=1, sort="id desc", as_obj=False)["items"]
        if len(results) == 0:
            return 0
        else:
            try:
                return int(results[0]["meta"]["rule_id"].split("_")[1])
            except (ValueError, KeyError):
                return 0

    def get_signature_last_revision_for_id(self, sid):
        query = "meta.rule_id:%s" % sid
        results = self.signature.search(query, offset=0, rows=1, sort="id desc", as_obj=False)["items"]
        if len(results) == 0:
            return 0
        else:
            try:
                return int(results[0]["meta"]["rule_version"])
            except (ValueError, KeyError):
                return 0

    def get_or_create_file_tree(self, submission, max_depth):
        if isinstance(submission, Model):
            submission = submission.as_primitives()

        num_files = len(list(set([x[:64] for x in submission['results']])))
        max_score = submission['max_score']

        cached_tree = self.submission_tree.get(submission['sid'], as_obj=False)
        if cached_tree:
            tree = json.loads(cached_tree['tree'])
            if self._is_valid_tree(tree, num_files, max_score):
                return tree

        files = {}
        scores = {}

        for key, item in self.result.multiget([x for x in submission['results'] if not x.endswith(".e")],
                                              as_obj=False).items():
            # Get files
            extracted = item['response']['extracted']
            if len(extracted) == 0:
                continue
            if key[:64] not in files:
                files[key[:64]] = []
            files[key[:64]].extend(extracted)

            # Get scores
            if key[:64] not in scores:
                scores[key[:64]] = 0

            scores[key[:64]] += item["result"]["score"]

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

                placeholder[child_p['sha256']] = {
                    "name": [child_p['name']],
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
                    "truncated": False,
                    "score": scores.get(sha256, 0),
                }

        cached_tree = {
            'expiry_ts': submission['expiry_ts'],
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

    def get_tag_list_from_keys(self, keys):
        if len(keys) == 0:
            return []
        keys = [x for x in list(keys) if not x.endswith(".e")]
        items = self.result.multiget(keys, as_obj=False)

        out = []
        for key, item in items.items():
            tags = item.get('result', {}).get('tags', [])
            [tag.update({"key": key}) for tag in tags]
            out.extend(tags)

        return out

    def list_all_services(self, as_obj=True, full=False):
        if full:
            return [self.ds.service.get(item.id, as_obj=as_obj)
                    for item in self.ds.service.stream_search("id:*", fl='id')]
        return [item for item in self.ds.service.stream_search("id:*", as_obj=as_obj)]

    def save_or_freshen_file(self, sha256, fileinfo, expiry, classification, cl_engine=forge.get_classification()):
        with Lock(f'save-or-freshen-file-{sha256}', 5):
            current_fileinfo = self.ds.file.get(sha256, as_obj=False) or {}

            # Remove control fields from file info and update current file info
            for x in ['classification', 'expiry_ts', 'seen']:
                fileinfo.pop(x, None)
            current_fileinfo.update(fileinfo)

            # Update expiry time
            current_fileinfo['expiry_ts'] = max(current_fileinfo.get('expiry_ts', expiry), expiry)

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
