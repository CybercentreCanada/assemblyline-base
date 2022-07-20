import logging
import os
import time
from typing import Optional, Iterable

# noinspection PyProtectedMember
from azure.core.exceptions import ServiceRequestError, DecodeError, \
    ResourceExistsError, ResourceNotFoundError, ClientAuthenticationError, \
    ResourceModifiedError, ResourceNotModifiedError, TooManyRedirectsError, ODataV4Error
from azure.identity import ClientSecretCredential
from azure.storage.blob import BlobServiceClient
from io import BytesIO

from assemblyline.common.exceptions import ChainAll
from assemblyline.filestore.transport.base import Transport, TransportException


"""
This class assumes a flat file structure in the Azure storage blob.
"""


@ChainAll(TransportException)
class TransportAzure(Transport):

    def __init__(self, base=None, access_key=None, tenant_id=None, client_id=None, client_secret=None,
                 host=None, connection_attempts=None):
        self.log = logging.getLogger('assemblyline.transport.azure')
        self.read_only = False
        self.connection_attempts: Optional[int] = connection_attempts

        # Get URL
        self.host = host
        self.endpoint_url = f"https://{self.host}"

        # Get container and base_path
        parts = base.strip("/").split("/", 1)
        self.blob_container = parts[0]
        if len(parts) > 1:
            self.base_path = parts[1]
        else:
            self.base_path = None

        # Get credentials
        if access_key:
            self.credential = access_key
        elif tenant_id and client_id and client_secret:
            self.credential = ClientSecretCredential(tenant_id=tenant_id,
                                                     client_id=client_id,
                                                     client_secret=client_secret)
        else:
            self.credential = None

        # Clients
        self.service_client = BlobServiceClient(account_url=self.endpoint_url, credential=self.credential)
        self.container_client = self.service_client.get_container_client(self.blob_container)

        # Init
        try:
            self.with_retries(self.container_client.get_container_properties)
        except TransportException as e:
            if not isinstance(e.cause, ResourceNotFoundError):
                raise
            try:
                self.with_retries(self.container_client.create_container)
            except TransportException as error:
                if not isinstance(error.cause, ResourceNotFoundError):
                    raise
                self.log.info('Failed to create container, we\'re most likely in read only mode')
                self.read_only = True

        def azure_normalize(path):
            # flatten path to just the basename
            if self.base_path:
                return os.path.join(self.base_path, os.path.basename(path))
            else:
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
                # These errors will be wrapped by TransportException
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
        try:
            self.with_retries(blob_client.delete_blob)
        except TransportException as error:
            # If its already not found, then consider it deleted.
            if not isinstance(error.cause, ResourceNotFoundError):
                raise

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
                self.with_retries(blob_client.upload_blob, data, overwrite=True)
            except TransportException as error:
                if not isinstance(error.cause, ResourceExistsError):
                    raise

    # Buffer based functions
    def get(self, path: str) -> bytes:
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
                self.with_retries(blob_client.upload_blob, file_io, overwrite=True)
            except TransportException as error:
                if not isinstance(error.cause, ResourceExistsError):
                    raise

    def list(self, prefix: Optional[str] = None) -> Iterable[str]:
        for blob in self.container_client.list_blobs(name_starts_with=prefix):
            yield blob['name']
