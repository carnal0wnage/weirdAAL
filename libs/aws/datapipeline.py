'''
Datapipleine functions for WeirdAAL
'''

import boto3
import botocore
import os
import pprint
import sys

pp = pprint.PrettyPrinter(indent=5, width=80)

session = boto3.Session()
credentials = session.get_credentials()
AWS_ACCESS_KEY_ID = credentials.access_key

# from http://docs.aws.amazon.com/general/latest/gr/rande.html
regions = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'af-south-1', 'ap-east-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3', 'ap-south-1', 'ap-southeast-1', 'ap-southeast-2', 'ca-central-1', 'cn-north-1', 'cn-northwest-1', 'eu-central-1', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-south-1', 'eu-north-1', 'me-south-1', 'sa-east-1', 'us-gov-west-1', 'us-gov-east-1']

'''
Code to get the AWS_ACCESS_KEY_ID from boto3
'''
session = boto3.Session()
credentials = session.get_credentials()
AWS_ACCESS_KEY_ID = credentials.access_key


def datapipeline_list_pipelines():
    '''
    Function to use the datapipeline boto3 library to list available pipelines
    '''
    print("### Printing Data Pipeline Pipelines ###")
    try:
        for region in regions:
            client = boto3.client('datapipeline', region_name=region)
            response = client.list_pipelines()
            print("### {} Data Pipelines ###" .format(region))
            if response.get('pipelineIdList') is None:
                print("{} likely does not have Data Pipeline permissions\n" .format(AWS_ACCESS_KEY_ID))
            elif len(response['pipelineIdList']) <= 0:
                print("[-] ListPipelines allowed for {} but no results [-]" .format(region))
            else:
                print("### {} Data Pipelines ###" .format(region))
                for pipes in response['pipelineIdList']:
                    pp.pprint(pipes)
                    print("\n")

    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidClientTokenId':
            sys.exit("{} : The AWS KEY IS INVALID. Exiting" .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'AccessDenied':
            print('{} : Is NOT a root key' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print("Unexpected error: {}" .format(e))
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")
