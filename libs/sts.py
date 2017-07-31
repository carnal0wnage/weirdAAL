import boto3
import botocore
import pprint

pp = pprint.PrettyPrinter(indent=5, width=80)

#from http://docs.aws.amazon.com/general/latest/gr/rande.html
regions = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ca-central-1', 'eu-central-1', 'eu-west-1', 'eu-west-2', 'ap-northeast-1', 'ap-northeast-2', 'ap-southeast-1', 'ap-southeast-2',  ]

def get_accountid(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
	try:
		client = boto3.client("sts", aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
		account_id = client.get_caller_identity()["Account"]
		print("Account Id: {}" .format(account_id))
	except KeyboardInterrupt:
		print("CTRL-C received, exiting...")

	return account_id

def get_accountid_all(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
	try:
		client = boto3.client("sts", aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
		account_id = client.get_caller_identity()["Account"]
		account_userid = client.get_caller_identity()["UserId"]
		account_arn = client.get_caller_identity()["Arn"]
		print("Account Id: {}" .format(account_id))
		print("Account UserID: {}" .format(account_userid) )
		print("Account ARN: {}" .format(account_arn) )
	except KeyboardInterrupt:
		print("CTRL-C received, exiting...")

	return account_id