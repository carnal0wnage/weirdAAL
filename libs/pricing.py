'''
Pricing Library
'''

import boto3
import botocore
import pprint
import sys

pp = pprint.PrettyPrinter(indent=5, width=80)

#from http://docs.aws.amazon.com/general/latest/gr/rande.html
regions = ['us-east-1', 'ap-south-1', ]


def pricing_describe_services(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
    try:
        for region in regions:
            client = boto3.client('pricing', aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY, region_name=region)
            response = client.describe_services()
            print(response)
            if response.get('Services') is None:
                print("{} likely does not have Pricing permissions\n" .format(AWS_ACCESS_KEY_ID))
            elif len(response['Services']) <= 0:
                print("[-] Describe Pricing Services allowed for {} but no results [-]" .format(region))
            else:
                print("### {} Services  ###" .format(region))
                for tables in response['ServiceCode']:
                    pp.pprint(tables)
                    print("\n")
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'UnauthorizedOperation':
            print('{} : (UnauthorizedOperation) when calling the Pricing DescribeServices' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print(e)
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")
