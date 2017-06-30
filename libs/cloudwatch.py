'''
cloudwatch functions
'''

import boto3
import botocore
import pprint
import sys,os

pp = pprint.PrettyPrinter(indent=5, width=80)

#from http://docs.aws.amazon.com/general/latest/gr/rande.html
regions = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ca-central-1', 'eu-central-1', 'eu-west-1', 'eu-west-2', 'ap-northeast-1', 'ap-northeast-2', 'ap-southeast-1', 'ap-southeast-2',  ]

def describe_alarms(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
    print("### Printing Cloudwatch Alarm Information ###")
    try:
    	for region in regions:
    		client = boto3.client('cloudwatch', aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY, region_name=region)

        	response = client.describe_alarms()
        	print"### {} Alarms ###" .format(region)
        	for alarm in response['MetricAlarms']:
        		pp.pprint(alarm)
        print("\n")
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidClientTokenId':
            sys.exit("{} : The AWS KEY IS INVALID. Exiting" .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'AccessDenied':
            print('{} : Is NOT a root key' .format(AWS_ACCESS_KEY_ID))
        else:
            print "Unexpected error: {}" .format(e)

def describe_alarm_history(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
    print("### Printing Cloudwatch Alarm History Information ###")
    try:
    	for region in regions:
    		client = boto3.client('cloudwatch', aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY,region_name=region)

        	response = client.describe_alarm_history()
        	#print response
        	if response.get('AlarmHistoryItems') is None:
        		print "{} likely does not have cloudwatch permissions\n" .format(AWS_ACCESS_KEY_ID)
        	elif len(response['AlarmHistoryItems']) <= 0:
        		print "[-] DecribeAlarmHistory allowed for {} but no results [-]" .format(region)
        	else:
        		print"### {} Alarm History ###" .format(region)
        		for history_item in response['AlarmHistoryItems']:
        			pp.pprint(history_item)
        print("\n")
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidClientTokenId':
            sys.exit("{} : The AWS KEY IS INVALID. Exiting" .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'AccessDenied':
            print('{} : Is NOT a root key' .format(AWS_ACCESS_KEY_ID))
        else:
            print "Unexpected error: {}" .format(e)

def list_metrics(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
    print("### Printing Cloudwatch List Metrics ###")
    try:
    	for region in regions:
    		client = boto3.client('cloudwatch', aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY,region_name=region)

        	response = client.list_metrics()
        	#print response
        	if response.get('Metrics') is None:
        		print "{} likely does not have cloudwatch permissions\n" .format(AWS_ACCESS_KEY_ID)
        	elif len(response['Metrics']) <= 0:
        		print "[-] ListMetrics allowed for {} but no results [-]" .format(region)
        	else:
        		print"### Listing Metrics for {} ###" .format(region)
        		for metrics in response['Metrics']:
        			pp.pprint(metrics)
        print("\n")
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidClientTokenId':
            sys.exit("{} : The AWS KEY IS INVALID. Exiting" .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'AccessDenied':
            print('{} : Is NOT a root key' .format(AWS_ACCESS_KEY_ID))
        else:
            print "Unexpected error: {}" .format(e)
