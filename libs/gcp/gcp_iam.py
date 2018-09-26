'''
GCP IAM functions for WeirdAAL
'''

import google.auth
import googleapiclient.discovery
import os
import sys

from google.oauth2 import service_account

from googleapiclient.errors import HttpError



# [START iam_list_keys]
def gcp_iam_list_keys(service_account_email, service):
    """Lists all keys for a service account."""

    # pylint: disable=no-member
    keys = service.projects().serviceAccounts().keys().list(
        name='projects/-/serviceAccounts/' + service_account_email).execute()

    for key in keys['keys']:
        print('Key: ' + key['name'])
# [END iam_list_keys]


# [START iam_list_service_accounts]
def gcp_iam_list_service_accounts(project_id, service):
    """Lists all service accounts for the current project."""

    # pylint: disable=no-member
    service_accounts = service.projects().serviceAccounts().list(
        name='projects/' + project_id).execute()

    for account in service_accounts['accounts']:
        print('Name: ' + account['name'])
        print('Email: ' + account['email'])
        print(' ')
    return service_accounts
# [END iam_list_service_accounts]

