from assemblyline.odm.models.alert import Alert
from assemblyline.odm.models.config import Config
from assemblyline.odm.models.emptyresult import EmptyResult
from assemblyline.odm.models.error import Error
from assemblyline.odm.models.file import File
from assemblyline.odm.models.filescore import FileScore
from assemblyline.odm.models.result import Result
from assemblyline.odm.models.service import Service
from assemblyline.odm.models.signature import Signature
from assemblyline.odm.models.submission import Submission
from assemblyline.odm.models.submission_tree import SubmissionTree
from assemblyline.odm.models.tc_signature import TCSignature
from assemblyline.odm.models.user import User
from assemblyline.odm.models.user_favorites import UserFavorites
from assemblyline.odm.models.user_options import UserOptions
from assemblyline.odm.models.vm import VM
from assemblyline.odm.models.workflow import Workflow


class AssemblylineDatastore(object):
    def __init__(self, datastore_object):
        self.ds = datastore_object
        self.ds.register('alert', Alert)
        self.ds.register('config', Config)
        self.ds.register('emptyresult', EmptyResult)
        self.ds.register('error', Error)
        self.ds.register('file', File)
        self.ds.register('filescore', FileScore)
        self.ds.register('result', Result)
        self.ds.register('service', Service)
        self.ds.register('signature', Signature)
        self.ds.register('submission', Submission)
        self.ds.register('submission_tree', SubmissionTree)
        self.ds.register('tc_signature', TCSignature)
        self.ds.register('user', User)
        self.ds.register('user_avatar')
        self.ds.register('user_favorites', UserFavorites)
        self.ds.register('user_options', UserOptions)
        self.ds.register('vm', VM)
        self.ds.register('workflow', Workflow)

    @property
    def alert(self):
        return self.ds.alert

    @property
    def config(self):
        return self.ds.config

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
    def user_options(self):
        return self.ds.user_options

    @property
    def vm(self):
        return self.ds.vm

    @property
    def workflow(self):
        return self.ds.workflow

    @staticmethod
    def create_empty_result_from_key(key, Classification, as_obj=True):
        sha256, svc_name, svc_version, _ = key.split(".", 3)
        svc_version = svc_version[1:]

        data = Result({
            "classification": Classification.UNRESTRICTED,
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

    def get_multiple_results(self, keys, Classification, as_obj=False):
        empties = {k: self.create_empty_result_from_key(k, Classification, as_obj=as_obj)
                   for k in keys if k.endswith(".e")}
        keys = [k for k in keys if not k.endswith(".e")]
        results = self.result.multiget(keys, as_dictionary=True, as_obj=as_obj)
        results.update(empties)
        return results

    def get_single_result(self, key, Classification, as_obj=False):
        if key.endswith(".e"):
            data = self.create_empty_result_from_key(key, Classification, as_obj=as_obj)
        else:
            data = self.result.get(key, as_obj=False)

        return data

    def list_all_services(self, as_obj=True, full=False):
        if full:
            return [self.ds.service.get(item.id, as_obj=as_obj)
                    for item in self.ds.service.stream_search(f"{self.ds.ID}:*", fl=self.ds.ID)]
        return [item for item in self.ds.service.stream_search(f"{self.ds.ID}:*", as_obj=as_obj)]
