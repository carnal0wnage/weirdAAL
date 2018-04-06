'''
dynamoDB functions
'''

import boto3
import botocore
import pprint
import sys,os

pp = pprint.PrettyPrinter(indent=5, width=80)

#from http://docs.aws.amazon.com/general/latest/gr/rande.html
regions = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ca-central-1', 'eu-central-1', 'eu-west-1', 'eu-west-2', 'ap-northeast-1', 'ap-northeast-2', 'ap-southeast-1', 'ap-southeast-2',  ]

def list_dynamodb_tables(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
    print("### Printing DynamoDB Tables ###")
    try:
    	for region in regions:
    		client = boto3.client('dynamodb', aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY, region_name=region)

        	response = client.list_tables()
        	if response.get('TableNames') is None:
        		print("{} likely does not have DynamoDB permissions\n" .format(AWS_ACCESS_KEY_ID))
        	elif len(response['TableNames']) <= 0:
        		print("[-] ListTables allowed for {} but no results [-]" .format(region))
        	else:
        		print"### {} DynamoDB Tables ###" .format(region)
        		for tables in response['TableNames']:
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

def list_dynamodb_tables_detailed(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
    print("### Printing DynamoDB Tables ###")
    try:
    	for region in regions:
    		client = boto3.client('dynamodb', aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY, region_name=region)

        	response = client.list_tables()
        	if response.get('TableNames') is None:
        		print("{} likely does not have DynamoDB permissions\n" .format(AWS_ACCESS_KEY_ID))
        	elif len(response['TableNames']) <= 0:
        		print("[-] ListTables allowed for {} but no results [-]" .format(region))
        	else:
        		print"### {} DynamoDB Tables ###" .format(region)
        		for tables in response['TableNames']:
        			#pp.pprint(tables)
        			describe_table(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, tables, region)
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

def describe_table(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, table, region):
    print("### Describing DynamoDB Table: {} ###" .format(table))
    try:
    	client = boto3.client('dynamodb', aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY, region_name=region)

        response = client.describe_table(TableName=table)
        if response.get('Table') is None:
        	print("{} likely does not have DynamoDB permissions\n" .format(AWS_ACCESS_KEY_ID))
        elif len(response['Table']) <= 0:
        	print("[-] DescribeTable allowed for {} but no results [-]" .format(region))
        else:
        	print("TableArn: {}" .format(response['Table']['TableArn']))
        	print("AttributeDefinitions: {}" .format(response['Table']['AttributeDefinitions']))
        	print("ProvisionedThroughput: {}" .format(response['Table']['ProvisionedThroughput']))
        	print("TableSizeBytes: {}" .format(response['Table']['TableSizeBytes']))
        	print("TableName: {}" .format(response['Table']['TableName']))
        	print("TableStatus: {}" .format(response['Table']['TableStatus']))
        	print("KeySchema: {}" .format(response['Table']['KeySchema']))
        	print("ItemCount: {}" .format(response['Table']['ItemCount']))
        	print("CreationDateTime: {}" .format(response['Table']['CreationDateTime']))
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
