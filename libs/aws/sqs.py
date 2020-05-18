'''
SQS functions for WeirdAAL
'''

import boto3
import botocore
import pprint
import sys

pp = pprint.PrettyPrinter(indent=5, width=80)

# from https://docs.aws.amazon.com/general/latest/gr/rande.html#sqs_region
regions = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'af-south-1', 'ap-east-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3', 'ap-south-1', 'ap-southeast-1', 'ap-southeast-2', 'ca-central-1', 'cn-north-1', 'cn-northwest-1', 'eu-central-1', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-south-1', 'eu-north-1', 'me-south-1', 'sa-east-1', 'us-gov-west-1', 'us-gov-east-1']

'''
Code to get the AWS_ACCESS_KEY_ID from boto3
'''
session = boto3.Session()
credentials = session.get_credentials()
AWS_ACCESS_KEY_ID = credentials.access_key


def sqs_list_queues():
    '''
    SQS List Queues
    '''
    try:
        for region in regions:
            client = boto3.client("sqs", region_name=region)
            response = client.list_queues()
            if response.get('QueueUrls') is None:
                print("[-] ListQueues allowed for {} but no results [-]" .format(region))
            # THis isnt working need to test with one that works to get the QueueUrl attributes
            elif len(response['QueueUrls']) <= 0:
                print("[-] ListQueues allowed for {} but no results [-]" .format(region))
            else:
                print("[+] Listing queuesfor region: {} [+]" .format(region))
                for r in response['QueueUrls']:
                    pp.pprint(r)

    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidClientTokenId':
            sys.exit("{} : The AWS KEY IS INVALID. Exiting" .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'AccessDenied':
            print('{} : Does not have the required permissions' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print("Unexpected error: {}" .format(e))
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")
