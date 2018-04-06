#ec2 functions go here

import boto3
import botocore
import pprint

pp = pprint.PrettyPrinter(indent=5, width=80)

#from http://docs.aws.amazon.com/general/latest/gr/rande.html
regions = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ca-central-1', 'eu-central-1', 'eu-west-1', 'eu-west-2', 'ap-northeast-1', 'ap-northeast-2', 'ap-southeast-1', 'ap-southeast-2',  ]

# we are past the enumeration stage at this point assume you have key that works
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
			print(e)
	except KeyboardInterrupt:
		print("CTRL-C received, exiting...")


def get_instance_details(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
	try:
		for region in regions:
			client = boto3.client(
				'ec2',
				aws_access_key_id = AWS_ACCESS_KEY_ID,
				aws_secret_access_key = AWS_SECRET_ACCESS_KEY,
				region_name=region
			)

			instances = client.describe_instances()
			for r in instances['Reservations']:
				for i in r['Instances']:
					pp.pprint(i)

	except botocore.exceptions.ClientError as e:
		print(e)
	except KeyboardInterrupt:
		print("CTRL-C received, exiting...")

#show volumes sorted by instanceId ex: instanceID-->multiple volumes  less detail than get_instance_volume_details2
def get_instance_volume_details(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
	try:
		for region in regions:
			client = boto3.client(
				'ec2',
				aws_access_key_id = AWS_ACCESS_KEY_ID,
				aws_secret_access_key = AWS_SECRET_ACCESS_KEY,
				region_name=region
			)

			instances = client.describe_instances()
			for r in instances['Reservations']:
				for i in r['Instances']:
					volumes = client.describe_instance_attribute(InstanceId=i['InstanceId'], Attribute='blockDeviceMapping')
					print ("Instance ID: {} \n" .format(i['InstanceId']))
					pp.pprint(volumes)

	except botocore.exceptions.ClientError as e:
		print(e)
	except KeyboardInterrupt:
		print("CTRL-C received, exiting...")

#show volumes by instanceId but instanceID->volume1 of ID, instanceID->volume2 of ID but more details.
def get_instance_volume_details2(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
	try:
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
				print("InstandID:{} \n" .format(volume['Attachments'][0]['InstanceId']))
				pp.pprint(volume)
				print("\n")

	except botocore.exceptions.ClientError as e:
		print(e)
	except KeyboardInterrupt:
		print("CTRL-C received, exiting...")
