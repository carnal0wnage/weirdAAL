'''
utilities for working with SNS
'''

import boto3
import botocore
import sys

regions = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'af-south-1', 'ap-east-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3', 'ap-south-1', 'ap-southeast-1', 'ap-southeast-2', 'ca-central-1', 'cn-north-1', 'cn-northwest-1', 'eu-central-1', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-south-1', 'eu-north-1', 'me-south-1', 'sa-east-1', 'us-gov-west-1', 'us-gov-east-1']

session = boto3.Session()
credentials = session.get_credentials()
AWS_ACCESS_KEY_ID = credentials.access_key
topics_list = {}

def list_sns_topics(should_i_print=True):
    title = "SNS Topics"
    if should_i_print:
        print(title)
        print("-" * len(title))
    try:
        for region in regions:
            client = boto3.client('sns', region_name=region)
            topics = client.list_topics()
            if should_i_print:
                print(region)
                print("=" * len(region))
            if topics['Topics']:
                topics_list[region] = topics['Topics']
                if should_i_print:
                    for topic in topics['Topics']:
                        print(topic)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidClientTokenId':
            sys.exit("The AWS KEY IS INVALID. Exiting")
        if e.response['Error']['Code'] == 'AccessDenied':
            print('{} : Is NOT a root key' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print("Unexpected error: {}" .format(e))
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")

def list_sns_subscribers(topic,region):
    try:
        client = boto3.client('sns', region_name=region)
        result = client.list_subscriptions_by_topic(TopicArn=topic)
        subscriptions = result['Subscriptions']
        for sub in subscriptions:
            print("Subscription Arn: {}".format(sub['SubscriptionArn']))
            print("Protocol: {}".format(sub['Protocol']))
            print("Endpoint: {}".format(sub['Endpoint']))
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidClientTokenId':
            sys.exit("The AWS KEY IS INVALID. Exiting")
        if e.response['Error']['Code'] == 'AccessDenied':
            print('{} : Is NOT a root key' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'InvalidParameter':
            print('The region you provided ({}) is invalid for the Topic ARN. Are you sure this topic exists in this region?'.format(region))
        else:
            print("Unexpected error: {}" .format(e))
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")

def delete_sns_topic(topic, region):
    try:
        client = boto3.client('sns', region_name=region)
        action = client.delete_topic(TopicArn=topic)
        print("Deleted Topic: {}".format(topic))
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidClientTokenId':
            sys.exit("The AWS KEY IS INVALID. Exiting")
        if e.response['Error']['Code'] == 'AccessDenied':
            print('{} : Is NOT a root key' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'InvalidParameter':
            print('The region you provided ({}) is invalid for the Topic ARN. Are you sure this topic exists in this region?'.format(region))
        else:
            print("Unexpected error: {}" .format(e))
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")

def list_all_sns_subscribers():
    print("Scanning regions....")
    list_sns_topics(False)
    for region,topics in topics_list.items():
        for topic in topics:
            region_title = "Region: {}".format(region)
            print(region_title)
            print("=" * len(region_title))
            list_sns_subscribers(topic['TopicArn'],region)





def delete_sns_subscriber(endpoint, region):
    try:
        client = boto3.client('sns', region_name=region)
        action = client.delete_endpoint(EndpointArn=endpoint)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidClientTokenId':
            sys.exit("The AWS KEY IS INVALID. Exiting")
        if e.response['Error']['Code'] == 'AccessDenied':
            print('{} : Is NOT a root key' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'InvalidParameter':
            print('The region you provided ({}) is invalid for the Subscriber endpoint. Are you sure this subscriber exists in this region?'.format(region))
        else:
            print("Unexpected error: {}" .format(e))
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")
