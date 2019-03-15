import logging
import os
import tempfile
from io import StringIO, BytesIO

import boto3
from botocore.exceptions import ClientError
from botocore.vendored.requests.packages.urllib3 import disable_warnings

from assemblyline.common.exceptions import ChainAll
from assemblyline.filestore.transport.base import Transport, TransportException

disable_warnings()

"""
This class assumes a flat file structure in the S3 bucket.  This is due to the way the AL datastore currently handles
file paths for local/ftp datastores not playing nicely with s3 constraints.
"""


@ChainAll(TransportException)
class TransportS3(Transport):
    DEFAULT_HOST = "s3.amazonaws.com"

    def __init__(self, base=None, accesskey=None, secretkey=None, aws_region=None, s3_bucket="al-storage",
                 host=None, port=None, use_ssl=None, verify=True):
        self.log = logging.getLogger('assemblyline.transport.s3')
        self.base = base
        self.bucket = s3_bucket
        self.accesskey = accesskey

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

        self.client = boto3.client(
            "s3",
            aws_access_key_id=accesskey,
            aws_secret_access_key=secretkey,
            endpoint_url=self.endpoint_url,
            region_name=aws_region,
            use_ssl=self.use_ssl,
            verify=verify
        )

        bucket_exist = False
        for bucket in self.client.list_buckets()["Buckets"]:
            if bucket.get("Name", None) == self.bucket:
                bucket_exist = True
                break

        if not bucket_exist:
            self.client.create_bucket(Bucket=self.bucket)

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

    def delete(self, path):
        key = self.normalize(path)
        self.client.delete_object(Bucket=self.bucket, Key=key)

    def exists(self, path):
        # checks to see if KEY exists
        key = self.normalize(path)
        self.log.debug('Checking for existence of %s', key)
        try:
            self.client.head_object(Bucket=self.bucket, Key=key)
        except ClientError:
            return False

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
        self.client.download_file(self.bucket, key, dst_path)

    def upload(self, src_path, dst_path):
        dst_path = self.normalize(dst_path)
        # if file exists already, it will be overwritten
        self.client.upload_file(src_path, self.bucket, dst_path)

    # Buffer based functions
    def get(self, path):
        fd, dst_path = tempfile.mkstemp(prefix="s3_transport.", suffix=".download")
        os.close(fd)  # We don't need the file descriptor open

        self.download(path, dst_path)
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
            self.client.upload_fileobj(file_io, self.bucket, dst_path)