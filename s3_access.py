# !/usr/bin/env python
# encoding: utf-8


# !/usr/bin/env python
# encoding: utf-8

"""
@file: s3_access.py
@time: 2022/4/21 13:39
@author: Runstor
@software: pycharm
"""

import argparse
import logging
import re
import sys
from urllib.parse import unquote
import uuid

import boto3
import certifi
from botocore.client import Config


def get_logger(logger_name):
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(levelname)s - %(message)s')
    if not logger.handlers:
        file_log_handler = logging.StreamHandler(sys.stdout)
        file_log_handler.setLevel(logging.DEBUG)
        file_log_handler.setFormatter(formatter)
        logger.addHandler(file_log_handler)
    return logger


_logger = get_logger(__name__)

PATH_STYLE_URL = "path"
VIRTUAL_HOST_STYLE_URL = "virtual"


class S3Driver(object):
    """
    s3 api driver
    """

    @property
    def string(self):
        return f"<S3Driver-%({self.name})>"

    def __init__(self, access_key, secret_key, endpoint,
                 region=None, enable_ssl=False, addressing=PATH_STYLE_URL, schema="http", port=80,
                 timeout=1200, max_attempts=4):
        self.name = self.__get_endpoint_url(schema, port, endpoint)
        _logger.debug("S3Driver __init__ __get_endpoint_url -> `{}`".format(self.name))

        self.client = boto3.client(
            's3',
            region_name=region,
            endpoint_url=self.name,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            verify=certifi.where() if enable_ssl else False,
            use_ssl=enable_ssl,
            config=Config(connect_timeout=timeout,
                          max_pool_connections=4,
                          retries={"max_attempts": max_attempts},
                          s3={'addressing_style': addressing},
                          )
        )

    @staticmethod
    def __get_endpoint_url(schema, default_port, host):
        assert isinstance(host, str)

        if not host.startswith("http"):
            host = "{}://{}".format(schema, host)

        # host中有端口，或指定的端口为[80\443]中的一个
        if re.findall(r':\d+$', host) or int(default_port) in [80, 443]:
            pass
        else:
            host = "{}:{}".format(host, default_port)
        return host

    def list_buckets(self):
        resp = self.client.list_buckets()
        """
        resp format:
        
        {
        'Buckets': [
                {
                    'Name': 'string',
                    'CreationDate': datetime(2015, 1, 1)
                },
            ],
            'Owner': {
                'DisplayName': 'string',
                'ID': 'string'
            }
        }
        """
        buckets = [b['Name'].encode('utf-8') if isinstance(b['Name'], bytes) else b['Name']
                   for b in resp.get("Buckets", list())]
        return [unquote(b.replace("+", "%20")) for b in buckets]

    def list_objects(self, bucket_name):
        resp = self.client.list_objects(Bucket=bucket_name)
        """
        resp format:
        
        {
            'IsTruncated': True|False,
            'Marker': 'string',
            'NextMarker': 'string',
            'Contents': [
                {
                    'Key': 'string',
                    'LastModified': datetime(2015, 1, 1),
                    'ETag': 'string',
                    'Size': 123,
                    'StorageClass': 'STANDARD'|'REDUCED_REDUNDANCY'|'GLACIER'|'...TODO'
                    'Owner': {
                        'DisplayName': 'string',
                        'ID': 'string'
                    }
                },
            ],
            'Name': 'string',
            'Prefix': 'string',
            'Delimiter': 'string',
            'MaxKeys': 123,
            'CommonPrefixes': [
                {
                    'Prefix': 'string'
                },
            ],
            'EncodingType': 'url'
        }
        """
        os_ = resp.get("Contents", list())
        for o in os_:
            o['Key'] = unquote(o['Key'].replace("+", "%20"))
        return os_

    def head_bucket(self, bucket_name):
        resp = self.client.head_bucket(Bucket=bucket_name)
        """
        resp format:
        
        {
            'ResponseMetadata': {
                '...': '...',
            },
        }
        """
        return resp

    def head_object(self, bucket_name, object_name):
        resp = self.client.head_object(Bucket=bucket_name, Key=object_name)
        """
        resp format:
        
        {
            'DeleteMarker': True|False,
            'AcceptRanges': 'string',
            'Expiration': 'string',
            'Restore': 'string',
            'ArchiveStatus': 'ARCHIVE_ACCESS'|'DEEP_ARCHIVE_ACCESS',
            'LastModified': datetime(2015, 1, 1),
            'ContentLength': 123,
            'ETag': 'string',
            'MissingMeta': 123,
            'VersionId': 'string',
            'CacheControl': 'string',
            'ContentDisposition': 'string',
            'ContentEncoding': 'string',
            'ContentLanguage': 'string',
            'ContentType': 'string',
            'Expires': datetime(2015, 1, 1),
            'WebsiteRedirectLocation': 'string',
            'ServerSideEncryption': 'AES256'|'aws:kms',
            'Metadata': {
                'string': 'string'
            },
            'SSECustomerAlgorithm': 'string',
            'SSECustomerKeyMD5': 'string',
            'SSEKMSKeyId': 'string',
            'BucketKeyEnabled': True|False,
            'StorageClass': 'STANDARD'|'REDUCED_REDUNDANCY'|'STANDARD_IA'
            'RequestCharged': 'requester',
            'ReplicationStatus': 'COMPLETE'|'PENDING'|'FAILED'|'REPLICA',
            'PartsCount': 123,
            'ObjectLockMode': 'GOVERNANCE'|'COMPLIANCE',
            'ObjectLockRetainUntilDate': datetime(2015, 1, 1),
            'ObjectLockLegalHoldStatus': 'ON'|'OFF'
        }
        """
        return resp

    def get_or_create_bucket(self, bucket_name):
        try:
            bucket = self.head_bucket(bucket_name)
        except self.client.exceptions.NoSuchBucket as _:
            _logger.debug("bucket `{}` not existed. will create".format(bucket_name))
            bucket = self.create_bucket(bucket_name)
        return bucket

    def create_bucket(self, bucket_name):
        try:
            self.client.create_bucket(Bucket=bucket_name)
        except (self.client.exceptions.BucketAlreadyExists, self.client.exceptions.BucketAlreadyOwnedByYou) as _:
            _logger.debug("bucket `{}` existed".format(bucket_name))
        return self.head_bucket(bucket_name)

    def get_object(self, bucket_name, object_name):
        try:
            object_ = self.client.get_object(Bucket=bucket_name, Key=object_name)
            """
            object_ format:
            
            {
                'Body': StreamingBody(),
                'DeleteMarker': True|False,
                'AcceptRanges': 'string',
                'Expiration': 'string',
                'Restore': 'string',
                'LastModified': datetime(2015, 1, 1),
                'ContentLength': 123,
                'ETag': 'string',
                'MissingMeta': 123,
                'VersionId': 'string',
                'CacheControl': 'string',
                'ContentDisposition': 'string',
                'ContentEncoding': 'string',
                'ContentLanguage': 'string',
                'ContentRange': 'string',
                'ContentType': 'string',
                'Expires': datetime(2015, 1, 1),
                'WebsiteRedirectLocation': 'string',
                'ServerSideEncryption': 'AES256'|'aws:kms',
                'Metadata': {
                    'string': 'string'
                },
                'SSECustomerAlgorithm': 'string',
                'SSECustomerKeyMD5': 'string',
                'SSEKMSKeyId': 'string',
                'BucketKeyEnabled': True|False,
                'StorageClass': 'STANDARD'
                'RequestCharged': 'requester',
                'ReplicationStatus': 'COMPLETE'|'PENDING'|'FAILED'|'REPLICA',
                'PartsCount': 123,
                'TagCount': 123,
                'ObjectLockMode': 'GOVERNANCE'|'COMPLIANCE',
                'ObjectLockRetainUntilDate': datetime(2015, 1, 1),
                'ObjectLockLegalHoldStatus': 'ON'|'OFF'
            }
            """
            return object_
        except (self.client.exceptions.NoSuchKey, self.client.exceptions.InvalidObjectState, Exception) as e:
            _logger.error("failed to get object named `{}`(type: {}) under bucket `{}`: {}".format(
                object_name, type(object_name), bucket_name, e))
            return None

    def put_object(self, bucket_name, object_name, stream=b''):
        resp = self.client.put_object(Body=stream, Bucket=bucket_name, Key=object_name)
        """
        resp format:
        
        {
            'Expiration': 'string',
            'ETag': 'string',
            'ServerSideEncryption': 'AES256'|'aws:kms',
            'VersionId': 'string',
            'SSECustomerAlgorithm': 'string',
            'SSECustomerKeyMD5': 'string',
            'SSEKMSKeyId': 'string',
            'SSEKMSEncryptionContext': 'string',
            'BucketKeyEnabled': True|False,
            'RequestCharged': 'requester'
        }
        """
        return resp

    def create_multipart_upload(self, bucket_name, object_name):
        resp = self.client.create_multipart_upload(Bucket=bucket_name, Key=object_name)
        """
        resp format:
        
        {
            'AbortDate': datetime(2015, 1, 1),
            'AbortRuleId': 'string',
            'Bucket': 'string',
            'Key': 'string',
            'UploadId': 'string',
            'ServerSideEncryption': 'AES256'|'aws:kms',
            'SSECustomerAlgorithm': 'string',
            'SSECustomerKeyMD5': 'string',
            'SSEKMSKeyId': 'string',
            'SSEKMSEncryptionContext': 'string',
            'BucketKeyEnabled': True|False,
            'RequestCharged': 'requester'
        }
        """
        return resp

    def abort_multipart_upload(self, bucket_name, object_name, upload_id):
        resp = self.client.abort_multipart_upload(Bucket=bucket_name, Key=object_name, UploadId=upload_id)
        """
        resp format:
        
        {
            'RequestCharged': 'requester'
        }
        """
        return resp

    def complete_multipart_upload(self, bucket_name, object_name, upload_id, parts):
        """
        xxx

        parts formatting: [{'ETag': 'string', 'PartNumber': 1}, ...]
        """
        resp = self.client.complete_multipart_upload(Bucket=bucket_name, Key=object_name, UploadId=upload_id,
                                                     MultipartUpload={'Parts': parts})
        """
        resp format:
        
        {
            'Location': 'string',
            'Bucket': 'string',
            'Key': 'string',
            'Expiration': 'string',
            'ETag': 'string',
            'ServerSideEncryption': 'AES256'|'aws:kms',
            'VersionId': 'string',
            'SSEKMSKeyId': 'string',
            'BucketKeyEnabled': True|False,
            'RequestCharged': 'requester'
        }
        """
        return resp

    def upload_part(self, bucket_name, object_name, upload_id, body=b'', part_number=1):
        resp = self.client.upload_part(Body=body, Bucket=bucket_name, Key=object_name, UploadId=upload_id,
                                       PartNumber=part_number)
        """
        resp format:
        
        {
            'ServerSideEncryption': 'AES256'|'aws:kms',
            'ETag': 'string',
            'SSECustomerAlgorithm': 'string',
            'SSECustomerKeyMD5': 'string',
            'SSEKMSKeyId': 'string',
            'BucketKeyEnabled': True|False,
            'RequestCharged': 'requester'
        }
        """
        return resp


def parse_args():
    parser = argparse.ArgumentParser(description='测试符合AWS-S3协议规范的对象存储')
    parser.add_argument('access', type=str, help='对象存储Access Key')
    parser.add_argument('secret', type=str, help='对象存储Secret Key')
    parser.add_argument('endpoint', type=str, help='对象存储Endpoint地址')
    parser.add_argument('region', type=str, default="cn", help='对象存储区域ID')
    parser.add_argument('ssl', type=bool, help='是否启用SSL证书')
    parser.add_argument('style', type=str, default=VIRTUAL_HOST_STYLE_URL, help='对象存储资源访问方式(path或virtual之一)')
    return parser.parse_args()


class TestS3(object):
    """
    测试s3
    """

    def __init__(self, access, secret, endpoint, region, ssl, style):
        self.client = S3Driver(access, secret, endpoint, region, ssl, style)
        self.bucket = uuid.uuid4().hex

    def __enter__(self):
        try:
            self.client.create_bucket(self.bucket)
        except Exception as e:
            _logger.error(f"创建桶失败，(异常: {e})")
        else:
            _logger.info(f"创建桶成功")

    def __exit__(self, exc_type, exc_val, exc_tb):
        _ = self
        _ = exc_tb
        _ = exc_val
        _ = exc_type

    def test(self):
        pass
