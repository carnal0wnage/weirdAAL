'''
Opsworks functions for WeirdAAL
'''

import boto3
import botocore
import pprint
import sys

pp = pprint.PrettyPrinter(indent=5, width=80)

# from http://docs.aws.amazon.com/general/latest/gr/rande.html
# http://docs.aws.amazon.com/general/latest/gr/rande.html#opsworks_region
regions = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'af-south-1', 'ap-east-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3', 'ap-south-1', 'ap-southeast-1', 'ap-southeast-2', 'ca-central-1', 'cn-north-1', 'cn-northwest-1', 'eu-central-1', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-south-1', 'eu-north-1', 'me-south-1', 'sa-east-1', 'us-gov-west-1', 'us-gov-east-1']

'''
Code to get the AWS_ACCESS_KEY_ID from boto3
'''
session = boto3.Session()
credentials = session.get_credentials()
AWS_ACCESS_KEY_ID = credentials.access_key


def opsworks_describe_stacks():
    '''
    Opsworks decribe stacks
    '''
    print('#### Opsworks Listing Stacks ####')
    try:
        for region in regions:
            client = boto3.client(
                'opsworks',
                region_name=region
            )
            response = client.describe_stacks()
            # print(response)
            if response.get('Stacks') is None:
                print("{} likely does not have Opsworks permissions\n" .format(AWS_ACCESS_KEY_ID))
            elif len(response['Stacks']) <= 0:
                print("[-] DescribeStacks allowed for {} but no results [-]" .format(region))
            else:  # THIS PART IS UNTESTED
                for r in response['Stacks']:
                    pp.pprint(r)
        print('\n')
    except botocore.exceptions.EndpointConnectionError as e:
        print("Unexpected error: {}" .format(e))

    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidClientTokenId':
            sys.exit("{} : The AWS KEY IS INVALID. Exiting" .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'EndpointConnectionError':
            print("[-] Cant connect to the {} endpoint [-]" .format(region))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print("Unexpected error: {}" .format(e))
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")


def opsworks_describe_user_profiles():
    '''
    Opsworks describe user profiles
    '''
    print('#### Opsworks Listing User Profiles ####')
    try:
        for region in regions:
            client = boto3.client(
                'opsworks',
                region_name=region
            )
            response = client.describe_user_profiles()
            # debug
            print(response)
            # if response.get('Stacks') is None:
            #    print("{} likely does not have Lambda permissions\n" .format(AWS_ACCESS_KEY_ID))
            # elif len(response['Stacks']) <= 0:
            #    print("[-] DescribeStacks allowed for {} but no results (everyone seems to have this permission) [-]\n" .format(region))
            # else:  # THIS PART IS UNTESTED
            #    for r in response['Stacks']:
            #        pp.pprint(r)
    except botocore.exceptions.EndpointConnectionError as e:
        print("Unexpected error: {}" .format(e))

    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidClientTokenId':
            sys.exit("{} : The AWS KEY IS INVALID. Exiting" .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'EndpointConnectionError':
            print("[-] Cant connect to the {} endpoint [-]" .format(region))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print("Unexpected error: {}" .format(e))
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")
