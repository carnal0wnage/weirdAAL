'''
Config Library
'''

import boto3
import botocore
import pprint
import sys

pp = pprint.PrettyPrinter(indent=5, width=80)

#from http://docs.aws.amazon.com/general/latest/gr/rande.html
regions = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ca-central-1', 'eu-central-1', 'eu-west-1', 'eu-west-2', 'ap-northeast-1', 'ap-northeast-2', 'ap-southeast-1', 'ap-southeast-2',  ]


def describe_configuration_recorders(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, region):
	response = {}
	try:
		client = boto3.client("config", aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY,region_name=region)

		response = client.describe_configuration_recorders()
		#print response
	except botocore.exceptions.ClientError as e:
		if e.response['Error']['Code'] == 'InvalidClientTokenId':
			sys.exit("The AWS KEY IS INVALID. Exiting")
		elif e.response['Error']['Code']  == 'UnrecognizedClientException':
			sys.exit("The AWS KEY IS INVALID. Exiting")
		elif e.response['Error']['Code'] == 'AccessDenied':
			print('[-] {} : does not have config access. Did you check first?' .format(AWS_ACCESS_KEY_ID))
			pass
		elif e.response['Error']['Code'] == 'AccessDeniedException':
			print('[-] {} : does not have config access. Did you check first?' .format(AWS_ACCESS_KEY_ID))
			pass
		else:
			print "Unexpected error: %s" % e

	return response

def describe_configuration_rules(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, region):
	response = []
	try:
		client = boto3.client("config", aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY,region_name=region)

		response = client.describe_config_rules()
		#print response
	except botocore.exceptions.ClientError as e:
		if e.response['Error']['Code'] == 'InvalidClientTokenId':
			sys.exit("The AWS KEY IS INVALID. Exiting")
		elif e.response['Error']['Code']  == 'UnrecognizedClientException':
			sys.exit("The AWS KEY IS INVALID. Exiting")
		elif e.response['Error']['Code'] == 'AccessDenied':
			print('[-] {} : does not have config access. Did you check first?' .format(AWS_ACCESS_KEY_ID))
			pass
		elif e.response['Error']['Code'] == 'AccessDeniedException':
			print('[-] {} : does not have config access. Did you check first?' .format(AWS_ACCESS_KEY_ID))
			pass
		else:
			print "Unexpected error: %s" % e

	return response