import logging
import os
import time

# noinspection PyProtectedMember
from azure.core.exceptions import *
from azure.storage.blob import BlobServiceClient
from io import BytesIO

from assemblyline.common.exceptions import ChainAll
from assemblyline.filestore.transport.base import Transport, TransportException


"""
This class assumes a flat file structure in the Azure storage blob.
"""


@ChainAll(TransportException)
class TransportAzure(Transport):

    def __init__(self, base=None, access_key=None, host=None, connection_attempts=None):
        self.log = logging.getLogger('assemblyline.transport.azure')
        self.read_only = False
        self.connection_attempts: int = connection_attempts

        # Data
        self.blob_container = base.strip("/")
        self.access_key = access_key
        self.host = host
        self.endpoint_url = f"https://{self.host}"

        # Clients
        self.service_client = BlobServiceClient(account_url=self.endpoint_url, credential=self.access_key)
        self.container_client = self.service_client.get_container_client(self.blob_container)

        # Init
        try:
            self.with_retries(self.container_client.get_container_properties)
        except ResourceNotFoundError:
            try:
                self.with_retries(self.container_client.create_container)
            except ResourceNotFoundError:
                self.log.info('Failed to create container, we\'re most likely in read only mode')
                self.read_only = True

        def azure_normalize(path):
            # flatten path to just the basename
            return os.path.basename(path)

        super(TransportAzure, self).__init__(normalize=azure_normalize)

    def __str__(self):
        return f"azure://{self.host}/{self.blob_container}/"

    def with_retries(self, func, *args, **kwargs):
        retries = 0
        while self.connection_attempts is None or retries <= self.connection_attempts:
            try:
                ret_val = func(*args, **kwargs)

                if retries:
                    self.log.info('Reconnected to Azure transport!')

                return ret_val

            except (ServiceRequestError, DecodeError, ResourceExistsError, ResourceNotFoundError,
                    ClientAuthenticationError, ResourceModifiedError, ResourceNotModifiedError,
                    TooManyRedirectsError, ODataV4Error):
                raise

            except Exception as e:
                self.log.warning(f"No connection to Azure transport "
                                 f"{os.path.join(self.endpoint_url, self.blob_container)}, retrying... "
                                 f"[{e.__class__.__name__}: {str(e)}]")
                time.sleep(0.25)
                retries += 1
        raise ConnectionError(f"Couldn't reach the requested azure endpoint {self.endpoint_url} inside retry limit")

    def delete(self, path):
        if self.read_only:
            raise TransportException("READ ONLY TRANSPORT: Method not allowed")

        key = self.normalize(path)
        blob_client = self.service_client.get_blob_client(self.blob_container, key)
        self.with_retries(blob_client.download_blob)

    def exists(self, path):
        key = self.normalize(path)
        blob_client = self.service_client.get_blob_client(self.blob_container, key)
        try:
            blob_client.get_blob_properties()
        except ResourceNotFoundError:
            return False

        return True

    def makedirs(self, path):
        # Does not need to do anything as azurestorage blob has a flat layout.
        pass

    # File based functions
    def download(self, src_path, dst_path):
        key = self.normalize(src_path)
        dir_path = os.path.dirname(dst_path)

        # create dst_path if it doesn't exist
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)

        # download the key from azure
        with open(dst_path, "wb") as my_blob:
            blob_client = self.service_client.get_blob_client(self.blob_container, key)
            blob_data = self.with_retries(blob_client.download_blob)
            blob_data.readinto(my_blob)

    def upload(self, src_path, dst_path):
        if self.read_only:
            raise TransportException("READ ONLY TRANSPORT: Method not allowed")

        key = self.normalize(dst_path)

        # if file exists already, it will be overwritten
        with open(src_path, "rb") as data:
            blob_client = self.service_client.get_blob_client(self.blob_container, key)
            try:
                self.with_retries(blob_client.upload_blob, data)
            except ResourceExistsError:
                pass

    # Buffer based functions
    def get(self, path):
        key = self.normalize(path)
        my_blob = BytesIO()

        blob_client = self.service_client.get_blob_client(self.blob_container, key)
        blob_data = self.with_retries(blob_client.download_blob)
        blob_data.readinto(my_blob)
        return my_blob.getvalue()

    def put(self, dst_path, content):
        if self.read_only:
            raise TransportException("READ ONLY TRANSPORT: Method not allowed")

        key = self.normalize(dst_path)
        if isinstance(content, str):
            content = content.encode('utf-8')

        with BytesIO(content) as file_io:
            blob_client = self.service_client.get_blob_client(self.blob_container, key)
            try:
                self.with_retries(blob_client.upload_blob, file_io)
            except ResourceExistsError:
                pass
