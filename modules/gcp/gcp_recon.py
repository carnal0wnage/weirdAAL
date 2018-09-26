'''
This module handles the core GCP recon functionality by asking all the services
that have functions that done have arguments if we can access them :-)
'''



from libs.gcp.gcp_iam import *
from libs.gcp.gcp_storage import *
from libs.gcp.gcp_bigquery import *

credentials = service_account.Credentials.from_service_account_file(
    filename=os.environ['GOOGLE_APPLICATION_CREDENTIALS'],
    scopes=['https://www.googleapis.com/auth/cloud-platform'])

service = googleapiclient.discovery.build(
    'iam', 'v1', credentials=credentials)

def module_gcp_recon_all():
    '''
    Main gcp_recon_all module - attempt to connect to each of the services to see if we have some privs
    python3 weirdAAL.py -m gcp_recon_all -t demo
    '''
    try:
        print("GCP IAM List Keys check")
        # print(credentials)
        gcp_iam_list_keys(credentials.service_account_email, service)
    except HttpError as e:
        # print(e)
        if e.resp.status in [403, 500, 503]:
            print("\tGCP IAM access denied for {}\n".format(credentials.service_account_email))
        else:
            print('{}\n'.format(e))
    except google.auth.exceptions.RefreshError as f:
        print(f)
        print("Service key is invalid exiting")
        sys.exit()

    try:
        print("GCP IAM list service accounts for the current project: {}.".format(credentials.project_id))
        # print(credentials)
        gcp_iam_list_service_accounts(credentials.project_id, service)
    except HttpError as e:
        # print(e)
        if e.resp.status in [403, 500, 503]:
            print("\tIAM access denied for {}\n".format(credentials.service_account_email))
        else:
            print('{}\n'.format(e))
    except google.auth.exceptions.RefreshError as f:
        print(f)
        print("Service key is invalid exiting")
        sys.exit()

    '''
    Storage bucket access checks
    '''
    try:
        print("GCP Storage check")
        buckets = gcp_storage_list_buckets(credentials)
        if buckets:
            print("\nAttempting to list bucket contents:")
            for a in buckets:
                print('Bucket: {}'.format(a))
                gcp_storage_list_blobs(credentials, a)
    except googleapiclient.errors.HttpError as e:
        print('{}\n'.format(e))
    except exceptions.Forbidden as e:
        print("\t Forbidden")
        print('{}\n'.format(e))
    except exceptions.PermissionDenied as e:
        print("\t PermissionDenied")
    except google.auth.exceptions.RefreshError as f:
        print(f)

    '''
    BigQuery access checks
    ''' 
    try:
        print("GCP BigQuery check")
        gcp_bigquery_list_datasets(credentials.project_id, credentials)
    except googleapiclient.errors.HttpError as e:
        print('{}\n'.format(e))
    except exceptions.Forbidden as e:
        print("\t Forbidden")
        print('{}\n'.format(e))
    except exceptions.PermissionDenied as e:
            print("\t PermissionDenied")
    except google.auth.exceptions.RefreshError as f:
        print(f)
