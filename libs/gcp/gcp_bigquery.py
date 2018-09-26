'''
GCP BigQuery functions for WeirdAAL
'''

import google.auth
import googleapiclient.discovery
import os
import sys

from google.oauth2 import service_account

from googleapiclient.errors import HttpError

from google.cloud import bigquery, exceptions
from google.cloud.exceptions import *


def gcp_bigquery_list_datasets(project_id, credentials):
    bigquery_client = bigquery.Client(project=credentials.project_id)
    datasets = list(bigquery_client.list_datasets())
    project = bigquery_client.project

    if datasets:
        print('Datasets in project {}:'.format(project))
        for dataset in datasets:  # API request(s)
            print('\t{}'.format(dataset.dataset_id))
    else:
        print('{} project does not contain any datasets.'.format(project))