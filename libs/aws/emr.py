'''
EMR functions for WeirdAAL
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


def list_clusters():
    '''
    List EMR Clusters
    '''
    print("### Printing EMR Clusters ###")
    try:
        for region in regions:
            client = boto3.client('emr', region_name=region)
            response = client.list_clusters()

            if response.get('Clusters') is None:
                print("{} likely does not have EMR permissions\n" .format(AWS_ACCESS_KEY_ID))
            elif len(response['Clusters']) <= 0:
                print("[-] ListClusters allowed for {} but no results [-]" .format(region))
            else:
                print("### {} EMR Clusters ###" .format(region))
                for app in response['Clusters']:
                    pp.pprint(app)
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


def list_security_configurations():
    '''
    List EMR Security Configurations
    '''
    print("### Printing EMR Security Configuration ###")
    try:
        for region in regions:
            client = boto3.client('emr', region_name=region)
            response = client.list_security_configurations()
            # print(response)

            if response.get('SecurityConfigurations') is None:
                print("{} likely does not have EMR permissions\n" .format(AWS_ACCESS_KEY_ID))
            elif len(response['SecurityConfigurations']) <= 0:
                print("[-] ListSecurityConfigurations allowed for {} but no results [-]" .format(region))
            else:
                print("### {} EMR Security Configuration ###" .format(region))
                for app in response['SecurityConfigurations']:
                    pp.pprint(app)
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
