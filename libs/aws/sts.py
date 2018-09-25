'''
STS libs for WeirdAAL
'''

import boto3
import botocore
import pprint
import sys

pp = pprint.PrettyPrinter(indent=5, width=80)

# from http://docs.aws.amazon.com/general/latest/gr/rande.html
# regions = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ca-central-1', 'eu-central-1', 'eu-west-1', 'eu-west-2', 'ap-northeast-1', 'ap-northeast-2', 'ap-southeast-1', 'ap-southeast-2',  ]

'''
Code to get the AWS_ACCESS_KEY_ID from boto3
'''
session = boto3.Session()
credentials = session.get_credentials()
AWS_ACCESS_KEY_ID = credentials.access_key


def sts_get_accountid():
    '''
    Use STS functions to get account data
    ex: Account Id: 14681234567
    '''
    try:
        client = boto3.client("sts")
        account_id = client.get_caller_identity()["Account"]
        print("Account Id: {}" .format(account_id))
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidClientTokenId':
            sys.exit("{} : The AWS KEY IS INVALID. Exiting" .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'EndpointConnectionError':
            print("[-] Cant connect to the region endpoint [-]")
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print("Unexpected error: {}" .format(e))
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")
    return account_id


def sts_get_accountid_all():
    '''
    Use STS functions to get account data (detailed)
    Prints AccountID, UserID, ARN
    '''
    try:
        client = boto3.client("sts")
        account_id = client.get_caller_identity()["Account"]
        account_userid = client.get_caller_identity()["UserId"]
        account_arn = client.get_caller_identity()["Arn"]
        print("Account Id: {}" .format(account_id))
        print("Account UserID: {}" .format(account_userid))
        print("Account ARN: {}" .format(account_arn))
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidClientTokenId':
            sys.exit("{} : The AWS KEY IS INVALID. Exiting" .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'EndpointConnectionError':
            print("[-] Cant connect to the region endpoint [-]")
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print("Unexpected error: {}" .format(e))
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")
    return account_id
