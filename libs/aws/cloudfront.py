'''
Cloudfront libs for WeirdAAL
'''

import boto3
import botocore
import pprint
import sys

pp = pprint.PrettyPrinter(indent=5, width=80)

# from http://docs.aws.amazon.com/general/latest/gr/rande.html
# cloudfront only supports us-east-1 https://docs.aws.amazon.com/general/latest/gr/cf_region.html
regions = ['us-east-1']

'''
Code to get the AWS_ACCESS_KEY_ID from boto3
'''
session = boto3.Session()
credentials = session.get_credentials()
AWS_ACCESS_KEY_ID = credentials.access_key


def cloudfront_list_distributions():
    '''
    CloudFront list distributions
    '''
    print("### Printing CloudFront Distributions ###")
    try:
        for region in regions:
            client = boto3.client('cloudfront', region_name=region)

            response = client.list_distributions()
            # print(response)
            if response.get('DistributionList') is None:
                print("{} likely does not have CloudFront permissions\n" .format(AWS_ACCESS_KEY_ID))
            elif len(response['DistributionList']) <= 0:
                print("[-] list_distributions allowed for {} but no results [-]" .format(region))
            else:
                print("### {} CloudFront Distributions ###" .format(region))
                for dist in response['DistributionList']['Items']:
                    pp.pprint(dist)
                    # pp.pprint(dist['Items'][0])
        print("\n")
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
