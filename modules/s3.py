'''
S3 module
'''

from libs.s3 import *


def module_s3_get_bucket_policy(*args):
    '''
    S3 list specific bucket acl and policy 
    python3 weirdAAL.py -m s3_get_bucket_policy -a 'bucket' -t yolo
    '''
    s3_get_bucket_policy(args[0][0])


def module_s3_list_buckets():
    '''
    S3 list buckets
    python3 weirdAAL.py -m s3_list_buckets -t yolo
    '''
    s3_get_objects_for_account()


def module_s3_list_buckets_and_policies():
    '''
    S3 list all buckets and their policies
    python3 weirdAAL.py -m s3_list_buckets_and_policies -t yolo
    '''
    s3_get_objects_for_account_detailed()


def module_s3_list_buckets_from_file(*args):
    '''
    S3 list buckets
    python3 weirdAAL.py -m s3_list_buckets_from_file -a 'bucket_list.txt' -t yolo
    '''
    s3_get_bucket_objects_from_file(args[0][0])