from assemblyline.odm.models.alert import Alert
from assemblyline.odm.models.config import Config
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

    def list_all_services(self, access_control=None, as_obj=True):
        return [item for item in self.ds.service.stream_search(f"{self.ds.ID}:*",
                                                               access_control=access_control, as_obj=as_obj)]
