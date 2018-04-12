'''
Firehose functions
'''

import boto3
import botocore
import os
import pprint
import sys

pp = pprint.PrettyPrinter(indent=5, width=80)

# from http://docs.aws.amazon.com/general/latest/gr/rande.html
regions = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'eu-central-1', 'eu-west-1', 'ap-northeast-1', 'ap-southeast-1', 'ap-southeast-2', ]

def firehose_list_delivery_streams(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
    print("### Printing Firehose Delivery Streams ###")
    try:
        for region in regions:
            client = boto3.client('firehose', aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY, region_name=region)

            response = client.list_delivery_streams()

            # print(response)
            if response['DeliveryStreamNames'] is None:
                print("{} likely does not have Firehose permissions\n" .format(AWS_ACCESS_KEY_ID))
            elif len(response['DeliveryStreamNames']) <= 0:
                print("[-] ListDeliveryStreams allowed for {} but no results [-]" .format(region))
            else:
                print("### {} Firehose Delivery Streams ###" .format(region))
                for stream in response['DeliveryStreamNames']:
                    pp.pprint(stream)
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


def firehose_describe_delivery_streams(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
    print("### Printing Firehose Delivery Streams & details ###")
    try:
        for region in regions:
            client = boto3.client('firehose', aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY, region_name=region)

            response = client.list_delivery_streams()

            # print(response)
            if response['DeliveryStreamNames'] is None:
                print("{} likely does not have Firehose permissions\n" .format(AWS_ACCESS_KEY_ID))
            elif len(response['DeliveryStreamNames']) <= 0:
                print("[-] ListDeliveryStreams allowed for {} but no results [-]" .format(region))
            else:
                print("### {} Firehose Delivery Streams ###" .format(region))
                for stream in response['DeliveryStreamNames']:
                	details = client.describe_delivery_stream(DeliveryStreamName=stream)
                	# This just prints the blob, needs to be cleaned up
                	print(details)
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
