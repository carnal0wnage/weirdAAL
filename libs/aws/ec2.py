'''
EC2 functions for WeirdAAL
'''
import base64
import boto3
import botocore
import datetime
import os
import pprint
import sys
import time

from libs.aws.sql import *

pp = pprint.PrettyPrinter(indent=5, width=80)

# from http://docs.aws.amazon.com/general/latest/gr/rande.html
regions = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'af-south-1', 'ap-east-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3', 'ap-south-1', 'ap-southeast-1', 'ap-southeast-2', 'ca-central-1', 'cn-north-1', 'cn-northwest-1', 'eu-central-1', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-south-1', 'eu-north-1', 'me-south-1', 'sa-east-1', 'us-gov-west-1', 'us-gov-east-1']

'''
Code to get the AWS_ACCESS_KEY_ID from boto3
'''
session = boto3.Session()
credentials = session.get_credentials()
AWS_ACCESS_KEY_ID = credentials.access_key


def review_encrypted_volumes():
    '''
    EC2 review encrypted volumes (describe volumes and check to see if encrypted or not)
    '''
    print("Reviewing EC2 Volumes... This may take a few....")
    not_encrypted = []
    encrypted = []
    try:
        with open("{}-volumes_list.txt" .format(AWS_ACCESS_KEY_ID), "w") as fout:
            for region in regions:
                try:
                    client = boto3.client('ec2', region_name=region)
                    response = client.describe_volumes(Filters=[{
                        'Name': 'status',
                        'Values': ['in-use']
                    }])['Volumes']
                except botocore.exceptions.ClientError as e:
                    if e.response['Error']['Code'] == 'UnauthorizedOperation':
                        print('{} : (UnauthorizedOperation) when calling the DescribeVolumes -- sure you have ec2 permissions?' .format(AWS_ACCESS_KEY_ID))
                        sys.exit()
                    else:
                        print(e)
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
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print(e)
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")


def describe_instances():
    '''
    EC2 Describe Instances
    '''
    try:
        for region in regions:
            try:
                client = boto3.client('ec2', region_name=region)
                response = client.describe_instances()
                # print(response)
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'UnauthorizedOperation':
                    print('{} : (UnauthorizedOperation) when calling the DescribeInstances in ({}) -- sure you have ec2 permissions?' .format(AWS_ACCESS_KEY_ID, region))
                    continue
                elif e.response['Error']['Code'] == 'AuthFailure':
                    print('{} : (AuthFailure) when calling the DescribeInstances in ({}) -- key is invalid or no permissions.' .format(AWS_ACCESS_KEY_ID, region))
                    continue
                elif e.response['Error']['Code'] == 'OptInRequired':
                    print('{} : (OptInRequired) Has permissions but isnt signed up for service in ({})- ' .format(AWS_ACCESS_KEY_ID, region))
                    continue
                else:
                    print(e)
                    continue
            if len(response['Reservations']) <= 0:
                print("[-] List instances allowed for {} but no results [-]" .format(region))
            else:
                print("[+] Listing instances for region: {} [+]" .format(region))
                db_logger = []
                for r in response['Reservations']:
                    db_logger.append(['ec2', 'DescribeInstances', str(r), AWS_ACCESS_KEY_ID, target, datetime.datetime.now()])
                    for i in r['Instances']:
                        pp.pprint(i)
                # logging to db here
                try:
                    # print(db_logger)
                    insert_sub_service_data(db_name, db_logger)
                except sqlite3.OperationalError as e:
                    print(e)
                    print("You need to set up the database...exiting")
                    sys.exit()
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'UnauthorizedOperation':
            print('{} : (UnauthorizedOperation) when calling the DescribeInstances -- sure you have ec2 permissions?' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print(e)
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")


def describe_instances_basic():
    '''
    Describe EC2 instances:
    print("InstanceID: {}, InstanceType: {}, State: {}, Launchtime: {}".format(instanceid, instancetype, state, launchtime))
    '''
    try:
        for region in regions:
            try:
                client = boto3.client('ec2', region_name=region)
                response = client.describe_instances()
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'UnauthorizedOperation':
                    print('{} : (UnauthorizedOperation) when calling the DescribeInstances in ({}) -- sure you have ec2 permissions?' .format(AWS_ACCESS_KEY_ID, region))
                    continue
                elif e.response['Error']['Code'] == 'AuthFailure':
                    print('{} : (AuthFailure) when calling the DescribeInstances in ({}) -- key is invalid or no permissions.' .format(AWS_ACCESS_KEY_ID, region))
                    continue
                elif e.response['Error']['Code'] == 'OptInRequired':
                    print('{} : (OptInRequired) Has permissions but isnt signed up for service in ({})- ' .format(AWS_ACCESS_KEY_ID, region))
                    continue
                else:
                    print(e)
                    continue
            if len(response['Reservations']) <= 0:
                print("[-] List instances allowed for {} but no results [-]" .format(region))
            else:
                # print (response)
                print("[+] Listing instances for region: {} [+]" .format(region))
                db_logger = []
                for r in response['Reservations']:
                    # logging the full blob
                    db_logger.append(['ec2', 'DescribeInstances', str(r), AWS_ACCESS_KEY_ID, target, datetime.datetime.now()])
                    for i in r['Instances']:
                        launchtime = i['LaunchTime']
                        instanceid = i['InstanceId']
                        instancetype = i['InstanceType']
                        state = i['State']
                        print("InstanceID: {}, InstanceType: {}, State: {}, Launchtime: {}".format(instanceid, instancetype, state, launchtime))
                # logging to db here
                try:
                    # print(db_logger)
                    insert_sub_service_data(db_name, db_logger)
                except sqlite3.OperationalError as e:
                    print(e)
                    print("You need to set up the database...exiting")
                    sys.exit()
        print("\n")
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'UnauthorizedOperation':
            print('{} : (UnauthorizedOperation) when calling the DescribeInstances -- sure you have ec2 permissions?' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print(e)
            next
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")


def write_instances_to_file():
    '''
    For each region write the instance IDs to file - AWSKEY-region.txt
    '''
    try:
        for region in regions:
            try:
                client = boto3.client('ec2', region_name=region)
                response = client.describe_instances()
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'UnauthorizedOperation':
                    print('{} : (UnauthorizedOperation) when calling the DescribeInstances -- sure you have required ec2 permissions?' .format(AWS_ACCESS_KEY_ID))
                    sys.exit()
                else:
                    print(e)
            if len(response['Reservations']) <= 0:
                print("[-] List instances allowed for {} but no results [-]" .format(region))
            else:
                # print (response)
                print("[+] Listing instances for region: {} [+]" .format(region))
                for r in response['Reservations']:
                    file = open('{}/loot/{}-{}.txt'.format(os.getcwd(), AWS_ACCESS_KEY_ID, region), "a")
                    for i in r['Instances']:
                        instanceid = i['InstanceId']
                        file.write("{}\n".format(instanceid))
                    file.close
        print("\n")
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'UnauthorizedOperation':
            print('{} : (UnauthorizedOperation) when calling the DescribeInstances -- sure you have ec2 permissions?' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print(e)
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")


def ec2_stop_instance_dryrun(instanceid, region):
    '''
    Attempt to stop (passing dryrun flag) the specified instanceID on the specififed region
    '''
    try:
        client = boto3.client('ec2', region_name=region)
        print("[INFO] Checking for permissions to stop instance (DryRun): {} on {} ** no ec2s were hurt during this ** [INFO]" .format(instanceid, region))
        response = client.stop_instances(DryRun=True, InstanceIds=['{}'.format(instanceid)])
        # print(response)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'DryRunOperation':
            print('[+] {} : Has permissions to stop the instance: {}... [+]' .format(AWS_ACCESS_KEY_ID, instanceid))
        elif e.response['Error']['Code'] == 'UnauthorizedOperation':
            print('{} : (UnauthorizedOperation) when calling stop_instances -- sure you have required ec2 permissions?' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print(e)
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")


def ec2_list_launchable_ami():
    '''
    For each region list launchable AMIs - equivalent to aws ec2 describe-images --executable-users self
    per documentation this doenst list AMIs you own.
    "The following command lists the AMIs for which you have explicit launch permissions. This list does not include any AMIs that you own."
    run ec2_list_owner_ami also to get a list of YOUR account's AMIs
    '''
    try:
        for region in regions:
            try:
                client = boto3.client('ec2', region_name=region)
                response = client.describe_images(ExecutableUsers=['self'])
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'UnauthorizedOperation':
                    print('{} : (UnauthorizedOperation) when calling the DescribeImages -- sure you have required ec2 permissions?' .format(AWS_ACCESS_KEY_ID))
                    sys.exit()
                else:
                    print(e)
            # print(response)
            if len(response['Images']) <= 0:
                print("[-] List instances allowed for {} but no results [-]" .format(region))
            else:
                # print(response)
                print("[+] Listing AMIs for region: {} [+]" .format(region))
                for r in response['Images']:
                    pp.pprint(r)
                print("\n")
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'UnauthorizedOperation':
            print('{} : (UnauthorizedOperation) when calling the DescribeInstances -- sure you have ec2 permissions?' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'OptInRequired':
            print('{} : Has permissions but isnt signed up for service - ' .format(AWS_ACCESS_KEY_ID))
        else:
            print(e)
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")


def ec2_list_owner_ami():
    '''
    For each region list your AMI's Owners=['self']
    '''
    try:
        for region in regions:
            try:
                client = boto3.client('ec2', region_name=region)
                # response = client.describe_images(Filters=[{'Name': 'is-public','Values': ['False',]},])
                response = client.describe_images(Owners=['self'])
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'UnauthorizedOperation':
                    print('{} : (UnauthorizedOperation) when calling the DescribeImages -- sure you have ec2 permissions?' .format(AWS_ACCESS_KEY_ID))
                    sys.exit()
                else:
                    print(e)
            # print(response)
            if len(response['Images']) <= 0:
                print("[-] DescribeImages allowed for {} but no results [-]" .format(region))
            else:
                # print(response)
                print("[+] Listing AMIs for region: {} [+]" .format(region))
                for r in response['Images']:
                    pp.pprint(r)
                print("\n")
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'UnauthorizedOperation':
            print('{} : (UnauthorizedOperation) when calling the DescribeInstances -- sure you have ec2 permissions?' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'OptInRequired':
            print('{} : Has permissions but isnt signed up for service - ' .format(AWS_ACCESS_KEY_ID))
        else:
            print(e)
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")


def get_instance_volume_details():
    '''
    show volumes sorted by instanceId ex: instanceID-->multiple volumes  less detail than get_instance_volume_details2
    '''
    try:
        for region in regions:
            try:
                client = boto3.client('ec2', region_name=region)
                instances = client.describe_instances()
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'UnauthorizedOperation':
                    print('{} : (UnauthorizedOperation) when calling the Describeinstances -- sure you have required ec2 permissions?' .format(AWS_ACCESS_KEY_ID))
                    sys.exit()
                else:
                    print(e)
            for r in instances['Reservations']:
                for i in r['Instances']:
                    volumes = client.describe_instance_attribute(InstanceId=i['InstanceId'], Attribute='blockDeviceMapping')
                    print("Instance ID: {} \n" .format(i['InstanceId']))
                    pp.pprint(volumes)

    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'UnauthorizedOperation':
            print('{} : (UnauthorizedOperation) when calling the DescribeVolumes -- sure you have required ec2 permissions?' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print(e)
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")


def get_instance_userdata():
    '''
    show volumes sorted by instanceId ex: instanceID-->multiple volumes  less detail than get_instance_volume_details2
    '''
    try:
        for region in regions:
            try:
                client = boto3.client('ec2', region_name=region)
                instances = client.describe_instances()
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'UnauthorizedOperation':
                    print('{} : (UnauthorizedOperation) when calling the DescribeInstances in ({}) -- sure you have ec2 permissions?' .format(AWS_ACCESS_KEY_ID, region))
                    continue
                elif e.response['Error']['Code'] == 'AuthFailure':
                    print('{} : (AuthFailure) when calling the DescribeInstances in ({}) -- key is invalid or no permissions.' .format(AWS_ACCESS_KEY_ID, region))
                    continue
                elif e.response['Error']['Code'] == 'OptInRequired':
                    print('{} : (OptInRequired) Has permissions but isnt signed up for service in ({})- ' .format(AWS_ACCESS_KEY_ID, region))
                    continue
                else:
                    print(e)
                    continue
            if len(instances['Reservations']) <= 0:
                print("[-] List instances allowed for {} but no results [-]" .format(region))
            else:
                for r in instances['Reservations']:
                    for i in r['Instances']:
                        try:
                            userData = client.describe_instance_attribute(InstanceId=i['InstanceId'], Attribute='userData')
                            print("Instance ID: {} \n" .format(i['InstanceId']))
                            if len(userData['UserData']['Value']) >= 0:
                                print("Decoded Userdata values:")
                                pp.pprint(base64.b64decode(userData['UserData']['Value']).decode("utf-8"))
                                print("\n")
                            else:
                                print("no Userdata for: {}\n".format(i['InstanceId']))
                        except KeyError:
                            next

    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'UnauthorizedOperation':
            print('{} : (UnauthorizedOperation) when calling the DescribeVolumes -- sure you have required ec2 permissions?' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print(e)
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")


def get_instance_volume_details2():
    '''
    show volumes by instanceId but instanceID->volume1 of ID, instanceID->volume2 of ID but more details.
    '''
    try:
        for region in regions:
            try:
                client = boto3.client('ec2', region_name=region)
                response = client.describe_volumes(Filters=[{
                    'Name': 'status',
                    'Values': ['in-use']
                }])['Volumes']
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'UnauthorizedOperation':
                    print('{} : (UnauthorizedOperation) when calling the DescribeVolumes -- sure you have the required ec2 permissions?' .format(AWS_ACCESS_KEY_ID))
                    sys.exit()
                else:
                    print(e)
            for volume in response:
                print("InstandID:{} \n" .format(volume['Attachments'][0]['InstanceId']))
                pp.pprint(volume)
                print("\n")

    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'UnauthorizedOperation':
            print('{} : (UnauthorizedOperation) when calling the DescribeVolumes -- sure you have the required ec2 permissions?' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print(e)
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")


def describe_elastic_addresses():
    '''
    Describe EC2 elastic addresses (loop through all regions)
    '''
    try:
        for region in regions:
            try:
                client = boto3.client('ec2', region_name=region)
                response = client.describe_addresses()
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'UnauthorizedOperation':
                    print('{} : (UnauthorizedOperation) when calling the DescribeAddresses -- sure you have required ec2 permissions?' .format(AWS_ACCESS_KEY_ID))
                    sys.exit()
                else:
                    print(e)
            if response.get('Addresses') is None:
                print("{} likely does not have EC2 permissions\n" .format(AWS_ACCESS_KEY_ID))
            elif len(response['Addresses']) <= 0:
                print("[-] DescribeAddresses allowed for {} but no results [-]" .format(region))
            else:
                # print (response)
                print("[+] Listing Addresses for region: {} [+]" .format(region))
                for r in response['Addresses']:
                    pp.pprint(r)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'UnauthorizedOperation':
            print('{} : (UnauthorizedOperation) when calling the DescribeInstances-- sure you have ec2 permissions?' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print(e)
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")

def describe_publicips():
    '''
    Describe EC2 Public IPs (loop through all regions)
    '''
    try:
        for region in regions:
            try:
                client = boto3.client('ec2', region_name=region)
                response = client.describe_network_interfaces()
                # print(response)
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'UnauthorizedOperation':
                    print('{} : (UnauthorizedOperation) when calling describe_network_interfaces -- sure you have required ec2 permissions?' .format(AWS_ACCESS_KEY_ID))
                    sys.exit()
                else:
                    print(e)
            if response.get('NetworkInterfaces') is None:
                print("{} likely does not have EC2 permissions\n" .format(AWS_ACCESS_KEY_ID))
            elif len(response['NetworkInterfaces']) <= 0:
                print("[-] DescribeNetworkInterfaces allowed for {} but no results [-]" .format(region))
            else:
                # print(response)
                print("[+] Listing Public IPs for region: {} [+]" .format(region))
                for r in response['NetworkInterfaces']:
                    if 'Association' in r:
                        pp.pprint(r['Association']['PublicIp'])
                    else:
                        #pp.pprint(r)
                        next
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'UnauthorizedOperation':
            print('{} : (UnauthorizedOperation) when calling the describe_network_interfaces-- sure you have ec2 permissions?' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print(e)
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")


def describe_network_interfaces():
    '''
    Describe EC2 network interfaces (loop through all regions)
    '''
    try:
        for region in regions:
            try:
                client = boto3.client('ec2', region_name=region)
                response = client.describe_network_interfaces()
                # print(response)
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'UnauthorizedOperation':
                    print('{} : (UnauthorizedOperation) when calling describe_network_interfaces -- sure you have required ec2 permissions?' .format(AWS_ACCESS_KEY_ID))
                    sys.exit()
                else:
                    print(e)
            if response.get('NetworkInterfaces') is None:
                print("{} likely does not have EC2 permissions\n" .format(AWS_ACCESS_KEY_ID))
            elif len(response['NetworkInterfaces']) <= 0:
                print("[-] DescribeNetworkInterfaces allowed for {} but no results [-]" .format(region))
            else:
                # print(response)
                print("[+] Listing Network Interfaces for region: {} [+]" .format(region))
                for r in response['NetworkInterfaces']:
                    pp.pprint(r)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'UnauthorizedOperation':
            print('{} : (UnauthorizedOperation) when calling the describe_network_interfaces -- sure you have ec2 permissions?' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print(e)
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")


def describe_route_tables():
    '''
    Describe EC2 route tables (loop through all regions)
    '''
    try:
        for region in regions:
            try:
                client = boto3.client('ec2', region_name=region)
                response = client.describe_route_tables()
                # print(response)
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'UnauthorizedOperation':
                    print('{} : (UnauthorizedOperation) when calling describe_route_tables -- sure you have required ec2 permissions?' .format(AWS_ACCESS_KEY_ID))
                    sys.exit()
                else:
                    print(e)
            if response.get('RouteTables') is None:
                print("{} likely does not have EC2 permissions\n" .format(AWS_ACCESS_KEY_ID))
            elif len(response['RouteTables']) <= 0:
                print("[-] DescribeRouteTables allowed for {} but no results [-]" .format(region))
            else:
                # print (response)
                print("[+] Listing Route Tables for region: {} [+]" .format(region))
                for r in response['RouteTables']:
                    pp.pprint(r)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'UnauthorizedOperation':
            print('{} : (UnauthorizedOperation) when calling the DescribeInstances-- sure you have ec2 permissions?' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print(e)
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")


def get_console_screenshot(instanceid, region):
    '''
    Get console screenshot of the specified InstanceID in the specified region
    '''
    try:
        client = boto3.client('ec2', region_name=region)
        print("[INFO] Checking for required permissions to screenshot: {} on {} [INFO]" .format(instanceid, region))
        response = client.get_console_screenshot(DryRun=True, InstanceId=instanceid, WakeUp=True)
        # print(response)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'DryRunOperation':
            print('[+] {} : Has permissions...proceeding with the screenshot attempt [+]' .format(AWS_ACCESS_KEY_ID))
            response = client.get_console_screenshot(DryRun=False, InstanceId=instanceid, WakeUp=True)
            print('[+] Writing screenshot to screenshots/{}.png [+]'.format(instanceid))
            file = open('{}/screenshots/{}.png'.format(os.getcwd(), instanceid), "wb")
            file.write(base64.b64decode(response['ImageData']))
            file.close
            # print(response)
        elif e.response['Error']['Code'] == 'UnauthorizedOperation':
            print('{} : (UnauthorizedOperation) when calling get_console_screenshot -- sure you have required ec2 permissions?' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print(e)
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")


def get_console_screenshot_all():
    '''
    loop through all regions and attempt to screenshot
    '''
    try:
        for region in regions:
            try:
                client = boto3.client('ec2', region_name=region)
                response = client.describe_instances()
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'UnauthorizedOperation':
                    print('{} : (UnauthorizedOperation) when calling describe_instances -- sure you have required ec2 permissions?' .format(AWS_ACCESS_KEY_ID))
                    sys.exit()
                else:
                    print(e)
            if len(response['Reservations']) <= 0:
                print("[-] List instances allowed for {} but no results [-]" .format(region))
            else:
                # print (response)
                print("[+] Listing instances for region: {} [+]" .format(region))
                for r in response['Reservations']:
                    for i in r['Instances']:
                        instanceid = i['InstanceId']
                        if i['State']['Name'] == "running":
                            try:
                                client = boto3.client('ec2', region_name=region)
                                print("[INFO] Checking for required permissions to screenshot: {} on {} [INFO]" .format(instanceid, region))
                                response = client.get_console_screenshot(DryRun=True, InstanceId=instanceid, WakeUp=True)
                            except botocore.exceptions.ClientError as e:
                                if e.response['Error']['Code'] == 'DryRunOperation':
                                    print('[+] {} : Has permissions...proceeding with the screenshot attempt [+]' .format(AWS_ACCESS_KEY_ID))
                                    response = client.get_console_screenshot(DryRun=False, InstanceId=instanceid, WakeUp=True)
                                    print('[+] Writing screenshot to screenshots/{}.png [+]'.format(instanceid))
                                    file = open('{}/screenshots/{}.png'.format(os.getcwd(), instanceid), "wb")
                                    file.write(base64.b64decode(response['ImageData']))
                                    file.close
                                    # print(response)
                                elif e.response['Error']['Code'] == 'UnauthorizedOperation':
                                    print('{} : (UnauthorizedOperation) when calling get_console_screenshot -- sure you have required ec2 permissions?' .format(AWS_ACCESS_KEY_ID))
                                elif e.response['Error']['Message'] == 'InternalError':
                                    print('{} : Has permissions but an internal error occured - check manually' .format(AWS_ACCESS_KEY_ID))
                                elif e.response['Error']['Code'] == 'InternalError':
                                    print('{} : Has permissions but an internal error occured - check manually' .format(AWS_ACCESS_KEY_ID))
                                elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
                                    print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
                                else:
                                    print(e)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'UnauthorizedOperation':
            print('{} : (UnauthorizedOperation) when calling the DescribeVolumes -- sure you have required ec2 permissions?' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print(e)
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")


def get_console_screenshot_all_region(region):
    '''
    Attempt to get screenshots of all EC2 instances in a specified region
    '''
    try:
            client = boto3.client('ec2', region_name=region)
            response = client.describe_instances()
            if len(response['Reservations']) <= 0:
                print("[-] List instances allowed for {} but no results [-]" .format(region))
            else:
                # print (response)
                print("[+] Listing instances for region: {} [+]" .format(region))
                for r in response['Reservations']:
                    for i in r['Instances']:
                        instanceid = i['InstanceId']
                        if i['State']['Name'] == "running":
                            try:
                                client = boto3.client('ec2', region_name=region)
                                print("[INFO] Checking for required permissions to screenshot: {} on {} [INFO]" .format(instanceid, region))
                                response = client.get_console_screenshot(DryRun=True, InstanceId=instanceid, WakeUp=True)
                            except botocore.exceptions.ClientError as e:
                                if e.response['Error']['Code'] == 'DryRunOperation':
                                    print('[+] {} : Has permissions...proceeding with the screenshot attempt [+]' .format(AWS_ACCESS_KEY_ID))
                                    response = client.get_console_screenshot(DryRun=False, InstanceId=instanceid, WakeUp=True)
                                    print('[+] Writing screenshot to screenshots/{}.png [+]'.format(instanceid))
                                    file = open('{}/screenshots/{}.png'.format(os.getcwd(), instanceid), "wb")
                                    file.write(base64.b64decode(response['ImageData']))
                                    file.close
                                    # print(response)
                                elif e.response['Error']['Code'] == 'UnauthorizedOperation':
                                    print('{} : (UnauthorizedOperation) when calling get_console_screenshot -- sure you have required ec2 permissions?' .format(AWS_ACCESS_KEY_ID))
                                elif e.response['Error']['Message'] == 'InternalError':
                                    print('{} : Has permissions but an internal error occured - check manually' .format(AWS_ACCESS_KEY_ID))
                                elif e.response['Error']['Code'] == 'InternalError':
                                    print('{} : Has permissions but an internal error occured - check manually' .format(AWS_ACCESS_KEY_ID))
                                elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
                                    print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
                                elif e.response['Error']['Code'] == 'InvalidInstanceID.NotFound':
                                    print('{} : instance not found' .format(AWS_ACCESS_KEY_ID))
                                else:
                                    print(e)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'UnauthorizedOperation':
            print('{} : (UnauthorizedOperation) when calling the DescribeVolumes -- sure you have required ec2 permissions?' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print(e)
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")


def get_console_screenshot_all_region_list(file, region):
    '''
    Read a list of ec2 instanceIDs and attempt to screenshot them. They need to be in the same region
    see write_instances_to_file to get a list of instances by region
    '''
    try:
        client = boto3.client('ec2', region_name=region)

        alist = [line.rstrip() for line in open(file)]
        for line in alist:
            try:
                print("[INFO] Checking for required permissions to screenshot: {} on {} [INFO]" .format(line, region))
                response = client.get_console_screenshot(DryRun=True, InstanceId=line, WakeUp=True)
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'DryRunOperation':
                    print('[+] {} : Has permissions...proceeding with the screenshot attempt [+]' .format(AWS_ACCESS_KEY_ID))
                    response = client.get_console_screenshot(DryRun=False, InstanceId=line, WakeUp=True)
                    print('[+] Writing screenshot to screenshots/{}.png [+]'.format(line))
                    file = open('{}/screenshots/{}.png'.format(os.getcwd(), line), "wb")
                    file.write(base64.b64decode(response['ImageData']))
                    file.close
                    # print(response)
                elif e.response['Error']['Code'] == 'UnauthorizedOperation':
                    print('{} : (UnauthorizedOperation) when calling get_console_screenshot -- sure you have required ec2 permissions?' .format(AWS_ACCESS_KEY_ID))
                elif e.response['Error']['Message'] == 'InternalError':
                    print('{} : Has permissions but an internal error occured - check manually' .format(AWS_ACCESS_KEY_ID))
                elif e.response['Error']['Code'] == 'InternalError':
                    print('{} : Has permissions but an internal error occured - check manually' .format(AWS_ACCESS_KEY_ID))
                elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
                    print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
                else:
                    print(e)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'UnauthorizedOperation':
            print('{} : (UnauthorizedOperation) when calling the DescribeVolumes -- sure you have required ec2 permissions?' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print(e)
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")


def get_console_output(instanceid, region):
    '''
    Attempt to get console output for specified instanceID and region
    '''
    try:
        client = boto3.client('ec2', region_name=region)
        print("[INFO] Checking for required permissions to get console output: {} on {} [INFO]" .format(instanceid, region))
        response = client.get_console_output(DryRun=True, InstanceId=instanceid)
        # print(response)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'DryRunOperation':
            print('[+] {} : Has permissions...proceeding with the console output attempt [+]' .format(AWS_ACCESS_KEY_ID))
            response = client.get_console_output(DryRun=False, InstanceId=instanceid)
            print('[+] Writing console output to loot/{}-console.txt [+]'.format(instanceid))
            file = open('{}/loot/{}-console.txt'.format(os.getcwd(), instanceid), "w")
            file.write(str(response['Output']))
            file.close
            # print(response)
        elif e.response['Error']['Code'] == 'UnauthorizedOperation':
            print('{} : (UnauthorizedOperation) when calling get_console_screenshot -- sure you have required ec2 permissions?' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print(e)
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")


def get_console_output_all():
    '''
    loop through all regions and attempt to get console output
    '''
    try:
        for region in regions:
            try:
                client = boto3.client('ec2', region_name=region)
                response = client.describe_instances()
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'UnauthorizedOperation':
                    print('{} : (UnauthorizedOperation) when calling get_console_screenshot -- sure you have required ec2 permissions?' .format(AWS_ACCESS_KEY_ID))
                    sys.exit()
                else:
                    print(e)
            if len(response['Reservations']) <= 0:
                print("[-] List instances allowed for {} but no results [-]" .format(region))
            else:
                # print (response)
                print("[+] Listing instances for region: {} [+]" .format(region))
                for r in response['Reservations']:
                    for i in r['Instances']:
                        instanceid = i['InstanceId']
                        if i['State']['Name'] == "running":
                            try:
                                client = boto3.client('ec2', region_name=region)
                                print("[INFO] Checking for required permissions to get console output: {} on {} [INFO]" .format(instanceid, region))
                                response = client.get_console_output(DryRun=True, InstanceId=instanceid)
                            except botocore.exceptions.ClientError as e:
                                if e.response['Error']['Code'] == 'DryRunOperation':
                                    print('[+] {} : Has permissions...proceeding with the console output attempt [+]' .format(AWS_ACCESS_KEY_ID))
                                    response = client.get_console_output(DryRun=False, InstanceId=instanceid)
                                    print('[+] Writing console output to loot/{}-console.txt [+]'.format(instanceid))
                                    if response.get('Output') is None:
                                        print("[-]no output from {} [-]".format(instanceid))
                                    else:
                                        file = open('{}/loot/{}-console.txt'.format(os.getcwd(), instanceid), "w")
                                        file.write(str(response['Output']))
                                        file.close
                                        # print(response)
                                elif e.response['Error']['Code'] == 'UnauthorizedOperation':
                                    print('{} : (UnauthorizedOperation) when calling get_console_screenshot -- sure you have required ec2 permissions?' .format(AWS_ACCESS_KEY_ID))
                                elif e.response['Error']['Message'] == 'InternalError':
                                    print('{} : Has permissions but an internal error occured - check manually' .format(AWS_ACCESS_KEY_ID))
                                elif e.response['Error']['Code'] == 'InternalError':
                                    print('{} : Has permissions but an internal error occured - check manually' .format(AWS_ACCESS_KEY_ID))
                                elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
                                    print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
                                else:
                                    print(e)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'UnauthorizedOperation':
            print('{} : (UnauthorizedOperation) when calling the DescribeVolumes -- sure you have required ec2 permissions?' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print(e)
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")


def get_console_output_all_region(region):
    '''
    loop thorugh a region and attempt to get the console output
    '''
    try:
            client = boto3.client('ec2', region_name=region)
            response = client.describe_instances()
            if len(response['Reservations']) <= 0:
                print("[-] List instances allowed for {} but no results [-]" .format(region))
            else:
                # print (response)
                print("[+] Listing instances for region: {} [+]" .format(region))
                for r in response['Reservations']:
                    for i in r['Instances']:
                        instanceid = i['InstanceId']
                        if i['State']['Name'] == "running":
                            try:
                                client = boto3.client('ec2', region_name=region)
                                print("[INFO] Checking for required permissions to get console output: {} on {} [INFO]" .format(instanceid, region))
                                response = client.get_console_output(DryRun=True, InstanceId=instanceid)
                            except botocore.exceptions.ClientError as e:
                                if e.response['Error']['Code'] == 'DryRunOperation':
                                    print('[+] {} : Has permissions...proceeding with the console output attempt [+]' .format(AWS_ACCESS_KEY_ID))
                                    response = client.get_console_output(DryRun=False, InstanceId=instanceid)
                                    print('[+] Writing console output to loot/{}-console.txt [+]'.format(instanceid))
                                    if response.get('Output') is None:
                                        print("[-]no output from {} [-]".format(instanceid))
                                    else:
                                        file = open('{}/loot/{}-console.txt'.format(os.getcwd(), instanceid), "w")
                                        file.write(str(response['Output']))
                                        file.close
                                        # print(response)
                                elif e.response['Error']['Code'] == 'UnauthorizedOperation':
                                    print('{} : (UnauthorizedOperation) when calling get_console_screenshot -- sure you have required ec2 permissions?' .format(AWS_ACCESS_KEY_ID))
                                elif e.response['Error']['Message'] == 'InternalError':
                                    print('{} : Has permissions but an internal error occured - check manually' .format(AWS_ACCESS_KEY_ID))
                                elif e.response['Error']['Code'] == 'InternalError':
                                    print('{} : Has permissions but an internal error occured - check manually' .format(AWS_ACCESS_KEY_ID))
                                elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
                                    print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
                                else:
                                    print(e)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'UnauthorizedOperation':
            print('{} : (UnauthorizedOperation) when calling the DescribeVolumes -- sure you have required ec2 permissions?' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print(e)
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")


def get_console_output_all_region_list(file, region):
    '''
    read in a file of instanceIDs for a region and attempt ot get the console output
    '''
    try:
        client = boto3.client('ec2', region_name=region)

        alist = [line.rstrip() for line in open(file)]
        for line in alist:
            try:
                print("[INFO] Checking for required permissions to get console output: {} on {} [INFO]" .format(line, region))
                response = client.get_console_output(DryRun=True, InstanceId=line)
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'DryRunOperation':
                    print('[+] {} : Has permissions...proceeding with the console output attempt [+]' .format(AWS_ACCESS_KEY_ID))
                    response = client.get_console_output(DryRun=False, InstanceId=line)
                    print('[+] Writing console output to loot/{}-console.txt [+]'.format(line))
                    file = open('{}/loot/{}-console.txt'.format(os.getcwd(), line), "w")
                    file.write(str(response['Output']))
                    file.close
                    # print(response)
                elif e.response['Error']['Code'] == 'UnauthorizedOperation':
                    print('{} : (UnauthorizedOperation) when calling get_console_screenshot -- sure you have required ec2 permissions?' .format(AWS_ACCESS_KEY_ID))
                elif e.response['Error']['Message'] == 'InternalError':
                    print('{} : Has permissions but an internal error occured - check manually' .format(AWS_ACCESS_KEY_ID))
                elif e.response['Error']['Code'] == 'InternalError':
                    print('{} : Has permissions but an internal error occured - check manually' .format(AWS_ACCESS_KEY_ID))
                elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
                    print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
                else:
                    print(e)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'UnauthorizedOperation':
            print('{} : (UnauthorizedOperation) when calling the DescribeVolumes -- sure you have required ec2 permissions?' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print(e)
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")

def ec2_get_snapshots():
    '''
    Describe snapshots in the account (loop through all regions)
    '''
    try:
        '''
        # commented out - RestorableByUserIds seems to get both owned and shared snapshots
        for region in regions:
            try:
                client = boto3.client('ec2', region_name=region)
                response = client.describe_snapshots(OwnerIds=[account_id],)
                # print(response)
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'UnauthorizedOperation':
                    print('{} : (UnauthorizedOperation) when calling describe_snapshots -- sure you have required ec2 permissions?' .format(AWS_ACCESS_KEY_ID))
                    sys.exit()
                else:
                    print(e)
            if response.get('Snapshots') is None:
                print("{} likely does not have EC2 permissions\n" .format(AWS_ACCESS_KEY_ID))
            elif len(response['Snapshots']) <= 0:
                print("[-] DescribeSnapshots allowed for {} but no results [-]" .format(region))
            else:
                # print (response)
                print("[+] Listing Snapshots for region: {} [+]" .format(region))
                for r in response['Snapshots']:
                    pp.pprint(r)
        '''
        print("Searching for snapshots that are \"RestorableByUserIds\" aka Owned by or Shared with your account ")
        for region in regions:
            try:
                client = boto3.client('ec2', region_name=region)
                response = client.describe_snapshots(RestorableByUserIds=['self'],)
                # print(response)
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'UnauthorizedOperation':
                    print('{} : (UnauthorizedOperation) when calling describe_snapshots -- sure you have required ec2 permissions?' .format(AWS_ACCESS_KEY_ID))
                    sys.exit()
                elif e.response['Error']['Code'] == 'AuthFailure':
                    print('{} : (AuthFailure) when calling the DescribeInstances in ({}) -- key is invalid or no permissions.' .format(AWS_ACCESS_KEY_ID, region))
                    continue
                else:
                    print(e)
            if response.get('Snapshots') is None:
                print("{} likely does not have EC2 permissions\n" .format(AWS_ACCESS_KEY_ID))
            elif len(response['Snapshots']) <= 0:
                print("[-] DescribeSnapshots allowed for {} but no results [-]" .format(region))
            else:
                # print (response)
                print("[+] Listing Shared Snapshots for region: {} [+]" .format(region))
                for r in response['Snapshots']:
                    pp.pprint(r)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'UnauthorizedOperation':
            print('{} : (UnauthorizedOperation) when calling the DescribeInstances-- sure you have ec2 permissions?' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print(e)
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")

def ec2_get_snapshots_by_accountid(account_id):
    '''
    Describe PUBLIC snapshots in the provided account (loop through all regions)
    '''
    try:
        #client = boto3.client("sts")
        #account_id = client.get_caller_identity()["Account"]
        print("Account Id: {}" .format(account_id))
        for region in regions:
            try:
                client = boto3.client('ec2', region_name=region)
                response = client.describe_snapshots(OwnerIds=[account_id],)
                # print(response)
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'UnauthorizedOperation':
                    print("{} : (UnauthorizedOperation) when calling describe_snapshots -- sure you have required ec2 permissions?" .format(AWS_ACCESS_KEY_ID))
                    sys.exit()
                elif e.response['Error']['Code'] == 'AuthFailure':
                    print('{} : (AuthFailure) when calling the DescribeInstances in ({}) -- key is invalid or no permissions.' .format(AWS_ACCESS_KEY_ID, region))
                    continue
                elif e.response['Error']['Code'] == 'InvalidUserID.Malformed':
                    print("Accountid is malformed - {}" .format(account_id))
                    sys.exit()
                else:
                    print(e)
            if response.get('Snapshots') is None:
                print("{} likely does not have EC2 permissions\n" .format(AWS_ACCESS_KEY_ID))
            elif len(response['Snapshots']) <= 0:
                print("[-] DescribeSnapshots allowed for {} but no results [-]" .format(region))
            else:
                # print (response)
                print("[+] Listing Snapshots for region: {} [+]" .format(region))
                for r in response['Snapshots']:
                    pp.pprint(r)

    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'UnauthorizedOperation':
            print('{} : (UnauthorizedOperation) when calling the DescribeInstances-- sure you have ec2 permissions?' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print(e)
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")