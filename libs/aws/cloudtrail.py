'''
Cloudtrail functions for WeirdAAL
'''

import boto3
import botocore
import os
import pprint
import sys

pp = pprint.PrettyPrinter(indent=5, width=80)

# from http://docs.aws.amazon.com/general/latest/gr/rande.html
regions = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'af-south-1', 'ap-east-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3', 'ap-south-1', 'ap-southeast-1', 'ap-southeast-2', 'ca-central-1', 'cn-north-1', 'cn-northwest-1', 'eu-central-1', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-south-1', 'eu-north-1', 'me-south-1', 'sa-east-1', 'us-gov-west-1', 'us-gov-east-1']
#  'cn-north-1', 'cn-northwest-1',  'us-gov-west-1' throwing An error occurred (UnrecognizedClientException) when calling the DescribeTrails operation: The security token included in the request is invalid.

'''
Code to get the AWS_ACCESS_KEY_ID from boto3
'''
try:
    session = boto3.Session()
    credentials = session.get_credentials()
    AWS_ACCESS_KEY_ID = credentials.access_key

#  Little hack to gracefully handle messed up .env/.aws credentials file as this is the first 
#  library that is loaded
except AttributeError as e:
    #print(e)
    print("[-] WeirdAAL had an eror loading the .env file [-]")
    print("[-] Make sure .env file exists OR you have at least one entry in .env [-]")
    sys.exit(1)
except botocore.exceptions.ConfigParseError as e:
    print("[-] {} [-]".format(e))
    print("[-] Make sure you dont have duplicate entries in your .env file [-]")
    sys.exit(1)


def describe_trails():
    '''
    Describe CloudTrail Trails for each region
    '''
    print("### Printing CloudTrail DescribeTrails ###")
    try:
        for region in regions:
            client = boto3.client('cloudtrail', region_name=region)
            response = client.describe_trails()

            if response['trailList'] is None:
                print("{} likely does not have CloudTrail permissions\n" .format(AWS_ACCESS_KEY_ID))
            elif len(response['trailList']) <= 0:
                print("[-] ListTrails allowed for {} but no results [-]" .format(region))
            else:
                print("### {} CloudTrail Trails ###" .format(region))
                for trail in response['trailList']:
                    pp.pprint(trail)
        print("\n")
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidClientTokenId':
            sys.exit("{} : The AWS KEY IS INVALID. Exiting" .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'AccessDenied':
            print('{} : Does not have the required permissions' .format(AWS_ACCESS_KEY_ID))
        # elif e.response['Error']['Code'] == 'UnrecognizedClientException':
        #    print('{} : UnrecognizedClientException error' .format(AWS_ACCESS_KEY_ID))
        #    pass
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print("Unexpected error: {}" .format(e))
            pass
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")


def list_public_keys():
    '''
    List public keys
    '''
    print("### Printing CloudTrail DescribeTrails ###")
    try:
        for region in regions:
            client = boto3.client('cloudtrail', region_name=region)
            response = client.list_public_keys()

            if response['PublicKeyList'] is None:
                print("{} likely does not have CloudTrail permissions\n" .format(AWS_ACCESS_KEY_ID))
            elif len(response['PublicKeyList']) <= 0:
                print("[-] PublicKeyList allowed for {} but no results [-]" .format(region))
            else:
                print("### {} CloudTrail Public Keys ###" .format(region))
                for keys in response['PublicKeyList']:
                    pp.pprint(keys)
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
            pass
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")


def stop_trail(TrailARN):
    '''
    Stop a specified trailARN
    Port of https://github.com/dagrz/aws_pwn/blob/master/stealth/disrupt_cloudtrail.py
    '''
    print("### Attempting to stop trail {} ###\n".format(TrailARN[0]))
    try:
        for region in regions:
            client = boto3.client('cloudtrail', region_name=region)
            response = client.describe_trails()

            if response['trailList'] is None:
                print("{} likely does not have CloudTrail permissions\n" .format(AWS_ACCESS_KEY_ID))
            elif len(response['trailList']) <= 0:
                print("[-] ListTrails allowed for {} but no results [-]" .format(region))
            else:
                for trail in response['trailList']:
                    HomeRegion = trail['HomeRegion']
                    myTrailARN = TrailARN[0]
                    # print(HomeRegion)
                    # print(myTrailARN)
        client2 = boto3.client('cloudtrail', region_name=HomeRegion)
        response = client2.stop_logging(Name=myTrailARN)
        print(response)
        print("\n")
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidClientTokenId':
            sys.exit("{} : The AWS KEY IS INVALID. Exiting" .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'AccessDenied':
            print('{} : Does not have the required permissions' .format(AWS_ACCESS_KEY_ID))
        # elif e.response['Error']['Code'] == 'UnrecognizedClientException':
        #    print('{} : UnrecognizedClientException error' .format(AWS_ACCESS_KEY_ID))
        #    pass
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print("Unexpected error: {}" .format(e))
            pass
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")


def delete_trail(TrailARN):
    '''
    Delete a specified trailARN
    Port of https://github.com/dagrz/aws_pwn/blob/master/stealth/disrupt_cloudtrail.py
    '''
    print("### Attempting to delete trail {} ###\n".format(TrailARN[0]))
    try:
        for region in regions:
            client = boto3.client('cloudtrail', region_name=region)
            response = client.describe_trails()

            if response['trailList'] is None:
                print("{} likely does not have CloudTrail permissions\n" .format(AWS_ACCESS_KEY_ID))
            elif len(response['trailList']) <= 0:
                print("[-] ListTrails allowed for {} but no results [-]" .format(region))
            else:
                for trail in response['trailList']:
                    HomeRegion = trail['HomeRegion']
                    myTrailARN = TrailARN[0]
                    # print(HomeRegion)
                    # print(myTrailARN)
        client2 = boto3.client('cloudtrail', region_name=HomeRegion)
        response = client2.delete_trail(Name=myTrailARN)
        print(response)
        print("\n")
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidClientTokenId':
            sys.exit("{} : The AWS KEY IS INVALID. Exiting" .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'AccessDenied':
            print('{} : Does not have the required permissions' .format(AWS_ACCESS_KEY_ID))
        # elif e.response['Error']['Code'] == 'UnrecognizedClientException':
        #    print('{} : UnrecognizedClientException error' .format(AWS_ACCESS_KEY_ID))
        #    pass
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print("Unexpected error: {}" .format(e))
            pass
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")
