'''
S3 module
'''

from libs.aws.s3 import *


def module_s3_get_bucket_policy(*args):
    '''
    S3 list specific bucket contents, acl and policy
    python3 weirdAAL.py -m s3_get_bucket_policy -a 'bucket' -t yolo
    '''
    s3_get_bucket_policy(args[0][0])


def module_s3_download_file(*args):
    '''
    S3 download a file from specified bucket
    python3 weirdAAL.py -m s3_download_file -a 'bucket','file' -t yolo
    '''
    s3_download_file(args[0][0], args[0][1])


def module_s3_upload_file(*args):
    '''
    S3 upload a file to the specified bucket
    python3 weirdAAL.py -m s3_upload_file -a 'bucket','source_file', 'dest_file' -t yolo
    '''
    s3_upload_file(args[0][0], args[0][1], args[0][2])


def module_s3_list_buckets():
    '''
    S3 list buckets for account
    python3 weirdAAL.py -m s3_list_buckets -t yolo
    '''
    s3_get_objects_for_account()


def module_s3_list_bucket_contents(*args):
    '''
    S3 list specific bucket contents
    python3 weirdAAL.py -m s3_list_bucket_contents -a "mybucket" -t yolo
    '''
    s3_list_bucket_contents(args[0][0])


def module_s3_list_buckets_and_policies():
    '''
    S3 list all buckets contents and their policies
    python3 weirdAAL.py -m s3_list_buckets_and_policies -t yolo
    '''
    s3_get_objects_for_account_detailed()


def module_s3_list_buckets_from_file(*args):
    '''
    S3 list buckets
    python3 weirdAAL.py -m s3_list_buckets_from_file -a 'bucket_list.txt' -t yolo
    '''
    s3_get_bucket_objects_from_file(args[0][0])


def module_s3_get_file_acl(*args):
    '''
    S3 get the ACL on a file
    python3 weirdAAL.py -m s3_get_file_acl -a 'bucket','file' -t yolo
    '''
    s3_get_file_acl(args[0][0], args[0][1])
