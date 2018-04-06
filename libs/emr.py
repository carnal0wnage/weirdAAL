'''
EMR functions
'''

import boto3
import botocore
import pprint
import sys,os

pp = pprint.PrettyPrinter(indent=5, width=80)

#from http://docs.aws.amazon.com/general/latest/gr/rande.html
regions = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ca-central-1', 'eu-central-1', 'eu-west-1', 'eu-west-2', 'ap-northeast-1', 'ap-northeast-2', 'ap-southeast-1', 'ap-southeast-2',  ]

def list_clusters(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
    print("### Printing EMR Clusters ###")
    try:
        for region in regions:
            client = boto3.client('emr', aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY, region_name=region)

            response = client.list_clusters()

            #print response

            if response.get('Clusters') is None:
                print("{} likely does not have EMR permissions\n" .format(AWS_ACCESS_KEY_ID))
            elif len(response['Clusters']) <= 0:
                print("[-] ListClusters allowed for {} but no results [-]" .format(region))
            else:
                print"### {} EMR Clusters ###" .format(region)
                for app in response['Clusters']:
                    pp.pprint(app)
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

def list_security_configurations(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
    print("### Printing EMR Security Configuration ###")
    try:
        for region in regions:
            client = boto3.client('emr', aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY, region_name=region)

            response = client.list_security_configurations()

            #print response

            if response.get('SecurityConfigurations') is None:
                print("{} likely does not have EMR permissions\n" .format(AWS_ACCESS_KEY_ID))
            elif len(response['SecurityConfigurations']) <= 0:
                print("[-] ListSecurityConfigurations allowed for {} but no results [-]" .format(region))
            else:
                print"### {} EMR Security Configuration ###" .format(region)
                for app in response['SecurityConfigurations']:
                    pp.pprint(app)
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

