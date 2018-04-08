'''
ECR functions
'''

import boto3
import botocore
import os
import pprint
import sys

pp = pprint.PrettyPrinter(indent=5, width=80)

# from http://docs.aws.amazon.com/general/latest/gr/rande.html
regions = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ca-central-1', 'eu-central-1', 'eu-west-1', 'eu-west-2', 'ap-northeast-1', 'ap-southeast-1', 'ap-southeast-2',  ]

def describe_repositories(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
    print("### Printing ECR Repositories ###")
    try:
        for region in regions:
            client = boto3.client('ecr', aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY, region_name=region)

            response = client.describe_repositories()

            # print response

            if response.get('repositories') is None:
                print("{} likely does not have ECR permissions\n" .format(AWS_ACCESS_KEY_ID))
            elif len(response['repositories']) <= 0:
                print("[-] DescribeRepositories allowed for {} but no results [-]" .format(region))
            else:
                print("### {} ECR Repositories ###" .format(region))
                for tables in response['repositories']:
                    pp.pprint(tables)
        print("\n")

    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidClientTokenId':
            sys.exit("{} : The AWS KEY IS INVALID. Exiting" .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'AccessDenied':
            print('{} : Does not have the required permissions' .format(AWS_ACCESS_KEY_ID))
        else:
            print("Unexpected error: {}" .format(e))
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")
