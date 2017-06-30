import boto3
import botocore
import pprint

pp = pprint.PrettyPrinter(indent=5, width=80)

#from http://docs.aws.amazon.com/general/latest/gr/rande.html
#http://docs.aws.amazon.com/general/latest/gr/rande.html#opsworks_region
regions = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', ]

#region = 'us-east-1'

def describe_stacks(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
	print('#### Listing Stacks ####')
	try:
		for region in regions:
			client = boto3.client(
				'opsworks',
				aws_access_key_id = AWS_ACCESS_KEY_ID,
				aws_secret_access_key = AWS_SECRET_ACCESS_KEY,
				region_name=region
			)
			response = client.describe_stacks()
			#debug
			print response
			if response.get('Stacks') is None:
				print "{} likely does not have Lambda permissions\n" .format(AWS_ACCESS_KEY_ID)
			elif len(response['Stacks']) <= 0:
				print "[-] DescribeStacks allowed for {} but no results (everyone seems to have this permission) [-]\n" .format(region)
			else: #THIS PART IS UNTESTED
				for r in response['Stacks']: 
					pp.pprint(r)
	except botocore.exceptions.EndpointConnectionError as e:
		print "Unexpected error: {}" .format(e)

	except botocore.exceptions.ClientError as e:
		if e.response['Error']['Code'] == 'InvalidClientTokenId':
			sys.exit("{} : The AWS KEY IS INVALID. Exiting" .format(AWS_ACCESS_KEY_ID))
		elif e.response['Error']['Code'] == 'EndpointConnectionError':
			print "[-] Cant connect to the {} endpoint [-]" .format(region)
		else:
			print "Unexpected error: {}" .format(e)
	except KeyboardInterrupt:
		print("CTRL-C received, exiting...")
