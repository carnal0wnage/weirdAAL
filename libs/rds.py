'''
RDS functions for WeirdAAL
'''

import boto3
import botocore
import pprint

pp = pprint.PrettyPrinter(indent=5, width=80)

# from http://docs.aws.amazon.com/general/latest/gr/rande.html
regions = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ca-central-1', 'eu-central-1', 'eu-west-1', 'eu-west-2', 'ap-northeast-1', 'ap-northeast-2', 'ap-southeast-1', 'ap-southeast-2',  ]

'''
Code to get the AWS_ACCESS_KEY_ID from boto3
'''
session = boto3.Session()
credentials = session.get_credentials()
AWS_ACCESS_KEY_ID = credentials.access_key


def describe_db_instances():
    print("### Printing RDS DB instances  ###")
    try:
        for region in regions:
            client = boto3.client(
                'rds',
                region_name=region
            )

            response = client.describe_db_instances()
            # print(response)
            if response.get('DBInstances') is None:
                print("{} likely does not have RDS permissions\n" .format(AWS_ACCESS_KEY_ID))
            elif len(response['DBInstances']) <= 0:
                print("[-] DescribeDBInstances allowed for {} but no results [-]" .format(region))
            else:
                print("### {} RDS DB Instances ###" .format(region))
                for r in response['DBInstances']:
                    for i in r['Instances']:
                        pp.pprint(i)
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
