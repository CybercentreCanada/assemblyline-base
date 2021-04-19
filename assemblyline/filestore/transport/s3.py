import boto3
import logging
import os
import tempfile

from botocore.exceptions import ClientError, EndpointConnectionError, ConnectionClosedError
from io import BytesIO

from assemblyline.common.exceptions import ChainAll
from assemblyline.filestore.transport.base import Transport, TransportException

try:
    from botocore.vendored.requests.packages.urllib3 import disable_warnings
except ImportError:
    from urllib3 import disable_warnings


disable_warnings()

"""
This class assumes a flat file structure in the S3 bucket.  This is due to the way the AL datastore currently handles
file paths for local/ftp datastores not playing nicely with s3 constraints.
"""


@ChainAll(TransportException)
class TransportS3(Transport):
    DEFAULT_HOST = "s3.amazonaws.com"

    def __init__(self, base=None, accesskey=None, secretkey=None, aws_region=None, s3_bucket="al-storage",
                 host=None, port=None, use_ssl=None, verify=True, connection_attempts=None):
        self.log = logging.getLogger('assemblyline.transport.s3')
        self.base = base
        self.bucket = s3_bucket
        self.accesskey = accesskey
        self.retry_limit: int = connection_attempts

        if use_ssl is None:
            self.use_ssl = True
        else:
            self.use_ssl = use_ssl

        if host is None:
            self.host = self.DEFAULT_HOST
        else:
            self.host = host

        if port is None:
            self.port = {True: 443, False: 80}[self.use_ssl]
        else:
            self.port = port

        self.scheme = {True: "https", False: "http"}[self.use_ssl]

        self.endpoint_url = "{scheme}://{host}:{port}".format(scheme=self.scheme, host=self.host, port=self.port)

        session = boto3.session.Session()
        self.client = session.client(
            "s3",
            aws_access_key_id=accesskey,
            aws_secret_access_key=secretkey,
            endpoint_url=self.endpoint_url,
            region_name=aws_region,
            use_ssl=self.use_ssl,
            verify=verify
        )

        bucket_exist = False
        try:
            self.with_retries(self.client.head_bucket, Bucket=self.bucket)
            bucket_exist = True
        except TransportException as e:
            if isinstance(e.cause, ClientError) and e.cause.response['Error']['Code'] == '404':
                pass
            else:
                raise

        if not bucket_exist:
            try:
                self.with_retries(self.client.create_bucket, Bucket=self.bucket)
            except TransportException as e:
                if isinstance(e.cause, ClientError) and e.cause.response['Error']['Code'] == "BucketAlreadyOwnedByYou":
                    # By the time that we listed the bucket an found it didn't exist, someone else created it.
                    pass
                else:
                    raise

        def s3_normalize(path):
            # flatten path to just the basename
            return os.path.basename(path)

        super(TransportS3, self).__init__(normalize=s3_normalize)

    def __str__(self):
        out = "s3://"
        if self.accesskey:
            out += "%s@" % self.accesskey
        out += "%s:%s" % (self.host, self.port)
        if self.bucket:
            out += "/%s" % self.bucket
        if self.base:
            out += self.base
        return out

    def with_retries(self, func, *args, **kwargs):
        retries = 0
        while self.retry_limit is None or retries <= self.retry_limit:
            try:
                ret_val = func(*args, **kwargs)

                if retries:
                    self.log.info('Reconnected to S3 transport!')

                return ret_val

            except (EndpointConnectionError, ConnectionClosedError):
                self.log.warning(f"No connection to S3 transport {self.endpoint_url}, retrying...")
                retries += 1
        raise ConnectionError(f"Couldn't connect to the requested S3 endpoint {self.endpoint_url} inside retry limit")

    def delete(self, path):
        key = self.normalize(path)
        self.with_retries(self.client.delete_object, Bucket=self.bucket, Key=key)

    def exists(self, path):
        # checks to see if KEY exists
        key = self.normalize(path)
        self.log.debug('Checking for existence of %s', key)
        try:
            self.with_retries(self.client.head_object, Bucket=self.bucket, Key=key)
        except TransportException as error:
            if isinstance(error.cause, ClientError):
                return False
            raise
        return True

    def makedirs(self, path):
        # Does not need to do anything as s3 has a flat layout.
        pass

    # File based functions
    def download(self, src_path, dst_path):
        key = self.normalize(src_path)
        dir_path = os.path.dirname(dst_path)
        # create dst_path if it doesn't exist
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)
        # download the key from s3
        self.with_retries(self.client.download_file, self.bucket, key, dst_path)

    def upload(self, src_path, dst_path):
        dst_path = self.normalize(dst_path)
        # if file exists already, it will be overwritten
        self.with_retries(self.client.upload_file, src_path, self.bucket, dst_path)

    # Buffer based functions
    def get(self, path):
        fd, dst_path = tempfile.mkstemp(prefix="s3_transport.", suffix=".download")
        os.close(fd)  # We don't need the file descriptor open

        self.with_retries(self.download, path, dst_path)
        try:
            with open(dst_path, "rb") as downloaded:
                return downloaded.read()
        finally:
            if os.path.exists(dst_path):
                os.remove(dst_path)

    def put(self, dst_path, content):
        dst_path = self.normalize(dst_path)
        if isinstance(content, str):
            content = content.encode('utf-8')

        with BytesIO(content) as file_io:
            self.with_retries(self.client.upload_fileobj, file_io, self.bucket, dst_path)
