#ec2 functions go here

import boto3
import botocore
import pprint

pp = pprint.PrettyPrinter(indent=5, width=80)

regions = ['us-east-1', 'us-west-2', 'ap-northeast-2', 'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'eu-central-1', 'eu-west-1']

# right now this will print a file with nothing if bad key, should fix at some point --otherwise can assume its a valid key 
# we are past the enumeration stage at this point
def review_encrypted_volumes(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
	print("Reviewing EC2 Volumes... This may take a few....")
	not_encrypted = []
	encrypted = []
	try:
		with open("{}-volumes_list.txt" .format(AWS_ACCESS_KEY_ID), "w") as fout:
			for region in regions:
				client = boto3.client(
					'ec2',
					aws_access_key_id = AWS_ACCESS_KEY_ID,
					aws_secret_access_key = AWS_SECRET_ACCESS_KEY,
					region_name=region
				)

				response = client.describe_volumes(Filters=[{
					'Name' : 'status',
					'Values' : ['in-use']
				}])['Volumes']
		
				for volume in response:
					if volume['Encrypted']:
						encrypted.append(volume['VolumeId'])
					else:
						not_encrypted.append(volume['VolumeId'])
					fout.write("\nEncrypted: " + str(volume['Encrypted']))
					for attachments in volume['Attachments']:
						fout.write("\nInstance ID: " + attachments['InstanceId'])
					fout.write("\nVolume ID: " + volume['VolumeId'])
					fout.write("\nRegion: " + region)
					fout.write("\n" + "-" * 40)
			print("Writing out results")
			fout.write("\nNot encrypted: " + str(len(not_encrypted)) + "\n")
			fout.write(pprint.pformat(not_encrypted))
			fout.write("\nEncrypted: " + str(len(encrypted)) + "\n")
			fout.write(pprint.pformat(encrypted))
	except botocore.exceptions.ClientError as e:
		if e.response['Error']['Code'] == 'UnauthorizedOperation':
			print('{} : (UnauthorizedOperation) when calling the DescribeVolumes -- sure you have ec2 permissions?' .format(AWS_ACCESS_KEY_ID))
		else:
			print e



