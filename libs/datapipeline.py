'''
datapipeline functions
'''

import boto3
import botocore
import pprint
import sys,os

pp = pprint.PrettyPrinter(indent=5, width=80)

#from http://docs.aws.amazon.com/general/latest/gr/rande.html
regions = ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-northeast-1', 'ap-southeast-2',  ]

def list_pipelines(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
    print("### Printing Data Pipeline Pipelines ###")
    try:
    	for region in regions:
    		client = boto3.client('datapipeline', aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY, region_name=region)

        	response = client.list_pipelines()
        	print"### {} Data Pipelines ###" .format(region)
        	if response.get('pipelineIdList') is None:
        		print "{} likely does not have Data Pipeline permissions\n" .format(AWS_ACCESS_KEY_ID)
        	elif len(response['pipelineIdList']) <= 0:
        		print "[-] ListPipelines allowed for {} but no results [-]" .format(region)
        	else:
        		print"### {} Data Pipelines ###" .format(region)
        		for pipes in response['pipelineIdList']:
        			pp.pprint(pipes)
        print("\n")
        	
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidClientTokenId':
            sys.exit("{} : The AWS KEY IS INVALID. Exiting" .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'AccessDenied':
            print('{} : Is NOT a root key' .format(AWS_ACCESS_KEY_ID))
        else:
            print "Unexpected error: {}" .format(e)
