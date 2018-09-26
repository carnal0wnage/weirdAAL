'''
GCP Storage functions for WeirdAAL
'''

import google.auth
import googleapiclient.discovery
import os
import sys

from google.oauth2 import service_account

from googleapiclient.errors import HttpError

from google.cloud import storage, exceptions
from google.cloud.exceptions import *



def gcp_storage_list_buckets(credentials):
    list_of_buckets = []
    '''list Google storage buckets for account'''
    storage_client = storage.Client()
    buckets = storage_client.list_buckets()
    for buck in buckets:
        print(buck.name)
        list_of_buckets.append(buck.name)
    return list_of_buckets


def gcp_storage_list_blobs(credentials, bucket_name):
    '''Lists all the blobs in the bucket.'''
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(bucket_name)

    blobs = bucket.list_blobs()

    for blob in blobs:
        print('\t{}'.format(blob.name))
    print('\n')