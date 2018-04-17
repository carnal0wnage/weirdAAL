import boto3
import botocore
import os
import pprint
import sys

'''
lamda functions for WeirdAAL
'''

pp = pprint.PrettyPrinter(indent=5, width=80)

# from http://docs.aws.amazon.com/general/latest/gr/rande.html
regions = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ca-central-1', 'eu-central-1', 'eu-west-1', 'eu-west-2', 'ap-northeast-1', 'ap-northeast-2', 'ap-southeast-1', 'ap-southeast-2', ]

'''
Code to get the AWS_ACCESS_KEY_ID from boto3
'''
session = boto3.Session()
credentials = session.get_credentials()
AWS_ACCESS_KEY_ID = credentials.access_key


def list_functions():
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


def list_event_source_mappings():
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
