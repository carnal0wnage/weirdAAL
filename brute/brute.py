import boto3
import botocore
import pprint

pp = pprint.PrettyPrinter(indent=5, width=80)



#bruteforce EC2 access

#from http://docs.aws.amazon.com/general/latest/gr/rande.html
regions = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ca-central-1', 'eu-central-1', 'eu-west-1', 'eu-west-2', 'ap-northeast-1', 'ap-northeast-2', 'ap-southeast-1', 'ap-southeast-2',  ]

def generic_permission_bruteforcer(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, tests):
    actions = []
    try:
        client = boto3.client('ec2', aws_access_key_id = AWS_ACCESS_KEY_ID, aws_secret_access_key = AWS_SECRET_ACCESS_KEY, region_name='ap-southeast-1')
    except Exception as e:
        print('Failed to connect: "{}"' .format(e.error_message))
        return actions
    
    actions = generic_method_bruteforcer(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, tests)
    if actions:
    	print "\nActions allowed are:"
        print actions

    return actions

def generic_method_bruteforcer(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, tests):
    actions = []
    client = boto3.client('ec2', aws_access_key_id = AWS_ACCESS_KEY_ID, aws_secret_access_key = AWS_SECRET_ACCESS_KEY, region_name='ap-southeast-1')
    for api_action, method_name, args, kwargs in tests:
        try:
            method = getattr(client, method_name)
            method(*args, **kwargs)
            #print method --wont return anything on dryrun
        except botocore.exceptions.ClientError as e:
        	if e.response['Error']['Code'] == 'DryRunOperation':
        		print('{} IS allowed' .format(api_action))
        		actions.append(api_action)
        	else:
        		print e   
        else:
            print('{} IS allowed' .format(api_action))
            actions.append(api_action)
    return actions

#http://boto3.readthedocs.io/en/latest/reference/services/ec2.html#client
def brute_ec2_perms(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
	print ("### Enumerating EC2 Permissions ###")
	perms =[]
	tests = [('DescribeInstances', 'describe_instances', (), {'DryRun':True}, ),
             ('DescribeInstanceStatus', 'describe_instance_status', (), {'DryRun':True}, ),
             ('DescribeImages', 'describe_images', (), {'DryRun':True, 'Owners': ['self',]} ),
             ('DescribeVolumes', 'describe_volumes', (), {'DryRun':True}, ),
             ('DescribeSnapshots', 'describe_snapshots', (), {'DryRun':True, 'OwnerIds': ['self',]} ),
             ('DescribeAccountAttributes', 'describe_account_attributes', (), {'DryRun':True}, ),
             ('DescribeAccounts', 'describe_addresses', (), {'DryRun':True}, ),
             ('DescribeAddresses','describe_addresses', (), {'DryRun':True}, ),
             ('DescribeAvailabilityZones', 'describe_availability_zones', (), {'DryRun':True}, ),
             ('DescribeBundleTasks', 'describe_bundle_tasks', (), {'DryRun':True}, ),
             ('DescribeClassicLinkInstances','describe_classic_link_instances', (), {'DryRun':True}, ),
             ('DescribeConversionTasks', 'describe_conversion_tasks', (), {'DryRun':True}, ),
             ('DescribeCustomerGateways', 'describe_customer_gateways', (), {'DryRun':True}, ),
             ('DescribeDhcpOptions', 'describe_dhcp_options', (), {'DryRun':True}, ),
             ('DescribeEgressOnlyInternetGateways','describe_egress_only_internet_gateways', (), {'DryRun':True}, ),


             #('', '', (), {'DryRun':True}, ),
             ]
	return generic_permission_bruteforcer(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, tests)


brute_ec2_perms(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)

