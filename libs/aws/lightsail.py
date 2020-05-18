'''
Lightsail functions for WeirdAAL
'''

import boto3
import botocore
import os
import pprint
import sys

pp = pprint.PrettyPrinter(indent=5, width=80)

'''
Code to get the AWS_ACCESS_KEY_ID from boto3
'''
session = boto3.Session()
credentials = session.get_credentials()
AWS_ACCESS_KEY_ID = credentials.access_key
AWS_SECRET_ACCESS_KEY = credentials.secret_key

# from http://docs.aws.amazon.com/general/latest/gr/rande.html
regions = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'af-south-1', 'ap-east-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3', 'ap-south-1', 'ap-southeast-1', 'ap-southeast-2', 'ca-central-1', 'cn-north-1', 'cn-northwest-1', 'eu-central-1', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-south-1', 'eu-north-1', 'me-south-1', 'sa-east-1', 'us-gov-west-1', 'us-gov-east-1']


def lightsail_get_instances():
    '''
    Lightsail Get Instances
    '''
    try:
        for region in regions:
            try:
                client = boto3.client('lightsail', region_name=region)
                response = client.get_instances()
                # print(response)
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'UnauthorizedOperation':
                    print('{} : (UnauthorizedOperation) when calling the DescribeInstances -- sure you have ec2 permissions?' .format(AWS_ACCESS_KEY_ID))
                    sys.exit()
                elif e.response['Error']['Code'] == 'AuthFailure':
                    print('{} : (AuthFailure) when calling the Get Instances -- key is invalid or no permissions.' .format(AWS_ACCESS_KEY_ID))
                    sys.exit()
                elif e.response['Error']['Code'] == 'AccessDeniedException':
                    print('{} : (AccessDeniedException) no permissions.' .format(AWS_ACCESS_KEY_ID))
                    sys.exit()

                else:
                    print(e)
            if len(response['instances']) <= 0:
                print("[-] get_instances allowed for {} but no results [-]" .format(region))
            else:
                print("[+] Listing instances for region: {} [+]" .format(region))
                # db_logger = []
                for r in response['instances']:
                    # db_logger.append(['ec2', 'DescribeInstances', str(r), AWS_ACCESS_KEY_ID, target, datetime.datetime.now()])
                    # for i in r['Instances']:
                    pp.pprint(r)
                # logging to db here
                # try:
                    # print(db_logger)
                    # insert_sub_service_data(db_name, db_logger)
                # except sqlite3.OperationalError as e:
                    # print(e)
                    # print("You need to set up the database...exiting")
                    # sys.exit()
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'UnauthorizedOperation':
            print('{} : (UnauthorizedOperation) when calling the Get Instances -- sure you have lightsail permissions?' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print(e)
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")
