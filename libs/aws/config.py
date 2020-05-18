'''
Config functions for WeirdAAL
'''

import boto3
import botocore
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


def describe_configuration_recorders(region):
    '''
    Describe Config recorders
    '''
    try:
        client = boto3.client("config", region_name=region)

        response = client.describe_configuration_recorders()
        region_name = "Region: %s\n" % region
        print(region_name)
        print("=" * len(region_name))
        if not response['ConfigurationRecorders']:
            print("No Recordings Found\n")
        else:
            for r in response['ConfigurationRecorders']:
                for k, v in r.items():
                    print("%s: %s" % (k, v))
                print("\n")
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidClientTokenId':
            sys.exit("The AWS KEY IS INVALID. Exiting")
        elif e.response['Error']['Code'] == 'UnrecognizedClientException':
            sys.exit("The AWS KEY IS INVALID. Exiting")
        elif e.response['Error']['Code'] == 'AccessDenied':
            print('[-] {} : does not have config access. Did you check first?' .format(AWS_ACCESS_KEY_ID))
            pass
        elif e.response['Error']['Code'] == 'AccessDeniedException':
            print('[-] {} : does not have config access. Did you check first?' .format(AWS_ACCESS_KEY_ID))
            pass
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print("Unexpected error: {}" .format(e))
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")


def describe_configuration_rules(region):
    '''
    Describe Config rules
    '''
    try:
        client = boto3.client("config", region_name=region)

        response = client.describe_config_rules()
        region_name = "Region: %s" % region
        print(region_name)
        print("=" * len(region_name))
        if not response['ConfigRules']:
            print("No Rules Found\n")
        else:
            for r in response['ConfigRules']:
                for k, v in r.items():
                    print("%s: %s" % (k, v))
                print("\n")
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidClientTokenId':
            sys.exit("The AWS KEY IS INVALID. Exiting")
        elif e.response['Error']['Code'] == 'UnrecognizedClientException':
            sys.exit("The AWS KEY IS INVALID. Exiting")
        elif e.response['Error']['Code'] == 'AccessDenied':
            print('[-] {} : does not have config access. Did you check first?' .format(AWS_ACCESS_KEY_ID))
            pass
        elif e.response['Error']['Code'] == 'AccessDeniedException':
            print('[-] {} : does not have config access. Did you check first?' .format(AWS_ACCESS_KEY_ID))
            pass
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print("Unexpected error: {}" .format(e))
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")


def delete_rule(rule_name, region):
    '''
    Attempt to delete the specified Config Rule
    '''
    try:
        client = boto3.client("config", region_name=region)
        client.delete_config_rule(ConfigRuleName=rule_name)
        print("Successfully deleted %s from %s!" % (rule_name, region))
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidClientTokenId':
            sys.exit("The AWS KEY IS INVALID. Exiting")
        elif e.response['Error']['Code'] == 'UnrecognizedClientException':
            sys.exit("The AWS KEY IS INVALID. Exiting")
        elif e.response['Error']['Code'] == 'AccessDenied':
            print('[-] {} : does not have config access. Did you check first?' .format(AWS_ACCESS_KEY_ID))
            pass
        elif e.response['Error']['Code'] == 'AccessDeniedException':
            print('[-] {} : does not have config access. Did you check first?' .format(AWS_ACCESS_KEY_ID))
            pass
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print("Unexpected error: {}" .format(e))
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")


def delete_recorder(recorder_name, region):
    '''
    Attempt to delete the specified Config recorder
    '''
    try:
        client = boto3.client("config", region_name=region)
        client.delete_configuration_recorder(ConfigurationRecorderName=recorder_name)
        print("Successfully deleted %s from %s!" % (recorder_name, region))
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidClientTokenId':
            sys.exit("The AWS KEY IS INVALID. Exiting")
        elif e.response['Error']['Code'] == 'UnrecognizedClientException':
            sys.exit("The AWS KEY IS INVALID. Exiting")
        elif e.response['Error']['Code'] == 'AccessDenied':
            print('[-] {} : does not have config access. Did you check first?' .format(AWS_ACCESS_KEY_ID))
            pass
        elif e.response['Error']['Code'] == 'AccessDeniedException':
            print('[-] {} : does not have config access. Did you check first?' .format(AWS_ACCESS_KEY_ID))
            pass
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print("Unexpected error: {}" .format(e))
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")


def list_all_config_rules():
    '''
    Get config rules for each region
    '''
    for region in regions:
        describe_configuration_rules(region)


def list_all_config_recorders():
    '''
    Get recorders for each region
    '''
    for region in regions:
        describe_configuration_recorders(region)


def delete_config_rule(rule_name, region):
    '''
    delete config rule (makes sure you passed a rule name)
    '''
    if rule_name:
        delete_rule(rule_name, region)


def delete_config_recorder(recorder_name, region):
    '''
    delete config recorder (makes sure you passed a recorder name)
    '''
    if recorder_name:
        delete_recorder(recorder_name, region)
