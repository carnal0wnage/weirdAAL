'''
SES functions for WeirdAAL
'''

import boto3
import botocore
import pprint
import sys

pp = pprint.PrettyPrinter(indent=5, width=80)

# https://docs.amazonaws.cn/en_us/general/latest/gr/ses.html
regions = ['us-east-1', 'us-west-2', 'ap-south-1', 'ap-southeast-2', 'ca-central-1', 'eu-central-1', 'eu-west-1', 'eu-west-2', 'sa-east-1', 'us-gov-west-1']

'''
Code to get the AWS_ACCESS_KEY_ID from boto3
'''
session = boto3.Session()
credentials = session.get_credentials()
AWS_ACCESS_KEY_ID = credentials.access_key


def list_identities():
    '''
    SES List Identities
    '''
    print("### Printing SES Identities  ###")
    try:
        for region in regions:
            client = boto3.client(
                'ses',
                region_name=region
            )

            response = client.list_identities()
            # print(response)
            if response.get('Identities') is None:
                print("{} likely does not have SES permissions\n" .format(AWS_ACCESS_KEY_ID))
            elif len(response['Identities']) <= 0:
                print("[-] ListIdentities allowed for {} but no results [-]" .format(region))
            else:
                print("### {} SES Identities ###" .format(region))
                for r in response['Identities']:
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


def get_send_statistics():
    '''
    SES get send statistics
    '''
    print("### Printing SES Send Statistics  ###")
    try:
        for region in regions:
            client = boto3.client(
                'ses',
                region_name=region
            )

            response = client.get_send_statistics()
            # print(response)
            if response.get('SendDataPoints') is None:
                print("{} likely does not have SES permissions\n" .format(AWS_ACCESS_KEY_ID))
            elif len(response['SendDataPoints']) <= 0:
                print("[-] GetSendStatistics allowed for {} but no results [-]" .format(region))
            else:
                print("### {} SES Send Statistics ###" .format(region))
                for r in response['SendDataPoints']:
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


def list_configuration_sets():
    '''
    SES List configuration sets
    '''
    print("### Printing SES Configuration Sets  ###")
    try:
        for region in regions:
            client = boto3.client(
                'ses',
                region_name=region
            )

            response = client.list_configuration_sets()
            # print(response)
            if response.get('ConfigurationSets') is None:
                print("{} likely does not have SES permissions\n" .format(AWS_ACCESS_KEY_ID))
            elif len(response['ConfigurationSets']) <= 0:
                print("[-] ListConfigurationSets allowed for {} but no results [-]" .format(region))
            else:
                print("### {} SES Configuration Sets ###" .format(region))
                for r in response['ConfigurationSets']:
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
