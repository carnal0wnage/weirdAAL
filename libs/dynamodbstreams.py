'''
dynamoDBstreams functions
'''

import boto3
import botocore
import pprint
import sys,os

pp = pprint.PrettyPrinter(indent=5, width=80)

#from http://docs.aws.amazon.com/general/latest/gr/rande.html
regions = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ca-central-1', 'eu-central-1', 'eu-west-1', 'eu-west-2', 'ap-northeast-1', 'ap-northeast-2', 'ap-southeast-1', 'ap-southeast-2',  ]


def list_dynamodbstreams(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
    print("### Printing DynamoDBstreams ###")
    try:
    	for region in regions:
    		client = boto3.client('dynamodbstreams', aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY, region_name=region)

        	response = client.list_streams()
        	if response.get('Streams') is None:
        		print "{} likely does not have DynamoDB permissions\n" .format(AWS_ACCESS_KEY_ID)
        	elif len(response['Streams']) <= 0:
        		print "[-] ListStreams allowed for {} but no results [-]" .format(region)
        	else:
        		print"### {} DynamoDB Streams ###" .format(region)
        		for streams in response['Streams']:
        			pp.pprint(streams)
        print("\n")
        	
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidClientTokenId':
            sys.exit("{} : The AWS KEY IS INVALID. Exiting" .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'AccessDenied':
            print('{} : Does not have the required permissions' .format(AWS_ACCESS_KEY_ID))
        else:
            print "Unexpected error: {}" .format(e)
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")