'''
Lambda functions for WeirdAAL
'''

import boto3
import botocore
import os
import pprint
import sys

pp = pprint.PrettyPrinter(indent=5, width=80)

# from http://docs.aws.amazon.com/general/latest/gr/rande.html
regions = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'af-south-1', 'ap-east-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3', 'ap-south-1', 'ap-southeast-1', 'ap-southeast-2', 'ca-central-1', 'cn-north-1', 'cn-northwest-1', 'eu-central-1', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-south-1', 'eu-north-1', 'me-south-1', 'sa-east-1', 'us-gov-west-1', 'us-gov-east-1']

'''
Code to get the AWS_ACCESS_KEY_ID from boto3
'''
session = boto3.Session()
credentials = session.get_credentials()
AWS_ACCESS_KEY_ID = credentials.access_key


def list_functions():
    '''
    List available lambda functions
    '''
    print("### Listing Lambda Functions ###")
    try:
        for region in regions:
            client = boto3.client('lambda', region_name=region)

            response = client.list_functions()
            # print(response)

            if response.get('Functions') is None:
                print("{} likely does not have Lambda permissions\n" .format(AWS_ACCESS_KEY_ID))
            elif len(response['Functions']) <= 0:
                print("[-] ListFunctions allowed for {} but no results [-]" .format(region))
            else:  # THIS PART IS UNTESTED
                for r in response['Functions']:
                    pp.pprint(r)
        print("\n")
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


def list_event_source_mappings():
    '''
    List Lambda event source mappings
    '''
    print("### Listing Lambda Event Source Mappings ###")
    try:
        for region in regions:
            client = boto3.client('lambda', region_name=region)

            response = client.list_event_source_mappings()

            if response.get('EventSourceMappings') is None:
                print("{} likely does not have Lambda permissions\n" .format(AWS_ACCESS_KEY_ID))
            elif len(response['EventSourceMappings']) <= 0:
                print("[-] ListEventSourceMappings allowed for {} but no results [-]" .format(region))
            else:
                for r in response['EventSourceMappings']:
                    # for i in r['Instances']:
                    pp.pprint(r)
        print("\n")
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


def lambda_get_function(functionname, region):
    '''
    Returns the configuration information of the Lambda function and a presigned URL link to the .zip file you uploaded with CreateFunction so you can download the .zip file. Note that the URL is valid for up to 10 minutes. The configuration information is the same information you provided as parameters when uploading the function.
    '''
    print("### Attempting to get function {} ###".format(functionname))
    try:
        client = boto3.client('lambda', region_name=region)

        response = client.get_function(FunctionName=functionname)
        # print(response)

        if response.get('Configuration') is None:
            print("{} likely does not have Lambda permissions\n" .format(AWS_ACCESS_KEY_ID))
        elif len(response['Configuration']) <= 0:
            print("[-] GetFunction allowed for {} but no results [-]" .format(region))
        else:
            print(response['Configuration'])
            print("\n")
            # print(response['Code'])
            print("Download link for {}:{}".format(functionname, response['Code']['Location']))
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


def lambda_get_account_settings():
    '''
    Returns Lambda account info
    '''
    print("### Attempting to get account settings ###")
    try:
        client = boto3.client('lambda')
        response = client.get_account_settings()
        # print(response)
        if response.get('AccountLimit') is None:
            print("{} likely does not have Lambda permissions\n" .format(AWS_ACCESS_KEY_ID))
        elif len(response['AccountLimit']) <= 0:
            print("[-] GetAccountSettings allowed for {} but no results [-]" .format(AWS_ACCESS_KEY_ID))
        else:
            print("AccountLimit:")
            pp.pprint(response['AccountLimit'])
            print("AccountUsage:")
            pp.pprint(response['AccountUsage'])
            print("\n")
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
