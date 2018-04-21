'''
EC2 functions for WeirdAAL
'''
import base64
import boto3
import botocore
import datetime
import os
import pprint
import time

from libs.sql import *

pp = pprint.PrettyPrinter(indent=5, width=80)

# from http://docs.aws.amazon.com/general/latest/gr/rande.html
regions = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ca-central-1', 'eu-central-1', 'eu-west-1', 'eu-west-2', 'ap-northeast-1', 'ap-northeast-2', 'ap-southeast-1', 'ap-southeast-2']

'''
Code to get the AWS_ACCESS_KEY_ID from boto3
'''
session = boto3.Session()
credentials = session.get_credentials()
AWS_ACCESS_KEY_ID = credentials.access_key


def review_encrypted_volumes():
    print("Reviewing EC2 Volumes... This may take a few....")
    not_encrypted = []
    encrypted = []
    try:
        with open("{}-volumes_list.txt" .format(AWS_ACCESS_KEY_ID), "w") as fout:
            for region in regions:
                client = boto3.client('ec2', region_name=region)
                response = client.describe_volumes(Filters=[{
                    'Name': 'status',
                    'Values': ['in-use']
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
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print(e)
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")


def describe_instances():
    try:
        for region in regions:
            client = boto3.client('ec2', region_name=region)
            response = client.describe_instances()
            if len(response['Reservations']) <= 0:
                print("[-] List instances allowed for {} but no results [-]" .format(region))
            else:
                print("[+] Listing instances for region: {} [+]" .format(region))
                db_logger = []
                for r in response['Reservations']:
                    db_logger.append(['ec2', 'DescribeInstances', str(r), AWS_ACCESS_KEY_ID, datetime.datetime.now()])
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
    try:
        for region in regions:
            client = boto3.client('ec2', region_name=region)
            response = client.describe_instances()
            if len(response['Reservations']) <= 0:
                print("[-] List instances allowed for {} but no results [-]" .format(region))
            else:
                # print (response)
                print("[+] Listing instances for region: {} [+]" .format(region))
                db_logger = []
                for r in response['Reservations']:
                    # logging the full blob
                    db_logger.append(['ec2', 'DescribeInstances', str(r), AWS_ACCESS_KEY_ID, datetime.datetime.now()])
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
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")


def write_instances_to_file():
    '''
    For each region write the instance IDs to file - AWSKEY-region.txt
    '''
    try:
        for region in regions:
            client = boto3.client('ec2', region_name=region)
            response = client.describe_instances()
            if len(response['Reservations']) <= 0:
                print("[-] List instances allowed for {} but no results [-]" .format(region))
            else:
                # print (response)
                print("[+] Listing instances for region: {} [+]" .format(region))
                for r in response['Reservations']:
                    file = open('{}/loot/{}-{}.txt'.format(os.getcwd(),AWS_ACCESS_KEY_ID,region), "a")
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




# show volumes sorted by instanceId ex: instanceID-->multiple volumes  less detail than get_instance_volume_details2


def get_instance_volume_details():
    try:
        for region in regions:
            client = boto3.client('ec2', region_name=region)

            instances = client.describe_instances()
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


def get_instance_volume_details2():
    '''
    show volumes by instanceId but instanceID->volume1 of ID, instanceID->volume2 of ID but more details.
    '''
    try:
        for region in regions:
            client = boto3.client('ec2', region_name=region)

            response = client.describe_volumes(Filters=[{
                    'Name': 'status',
                    'Values': ['in-use']
                }])['Volumes']
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


def describe_addresses():
    try:
        for region in regions:
            client = boto3.client('ec2', region_name=region)
            response = client.describe_addresses()
            # print(response)
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


def describe_network_interfaces():
    try:
        for region in regions:
            client = boto3.client('ec2', region_name=region)
            response = client.describe_network_interfaces()
            # print(response)
            if response.get('NetworkInterfaces') is None:
                print("{} likely does not have EC2 permissions\n" .format(AWS_ACCESS_KEY_ID))
            elif len(response['NetworkInterfaces']) <= 0:
                print("[-] DescribeNetworkInterfaces allowed for {} but no results [-]" .format(region))
            else:
                # print (response)
                print("[+] Listing Network Interfaces for region: {} [+]" .format(region))
                for r in response['NetworkInterfaces']:
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


def describe_route_tables():
    try:
        for region in regions:
            client = boto3.client('ec2', region_name=region)
            response = client.describe_route_tables()
            # print(response)
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
    try:
        client = boto3.client('ec2', region_name=region)
        print("[INFO] Checking for required permissions to screenshot: {} on {} [INFO]" .format(instanceid, region))
        response = client.get_console_screenshot(DryRun=True, InstanceId=instanceid,WakeUp=True)
        # print(response)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'DryRunOperation':
            print('[+] {} : Has permissions...proceeding with the screenshot attempt [+]' .format(AWS_ACCESS_KEY_ID))
            response = client.get_console_screenshot(DryRun=False, InstanceId=instanceid,WakeUp=True)
            print('[+] Writing screenshot to screenshots/{}.png [+]'.format(instanceid))
            file = open('{}/screenshots/{}.png'.format(os.getcwd(),instanceid), "wb")
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
    try:
        for region in regions:
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
                        try:
                            client = boto3.client('ec2', region_name=region)
                            print("[INFO] Checking for required permissions to screenshot: {} on {} [INFO]" .format(instanceid, region))
                            response = client.get_console_screenshot(DryRun=True, InstanceId=instanceid,WakeUp=True)
                        except botocore.exceptions.ClientError as e:
                            if e.response['Error']['Code'] == 'DryRunOperation':
                                print('[+] {} : Has permissions...proceeding with the screenshot attempt [+]' .format(AWS_ACCESS_KEY_ID))
                                response = client.get_console_screenshot(DryRun=False, InstanceId=instanceid,WakeUp=True)
                                print('[+] Writing screenshot to screenshots/{}.png [+]'.format(instanceid))
                                file = open('{}/screenshots/{}.png'.format(os.getcwd(),instanceid), "wb")
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
                        try:
                            client = boto3.client('ec2', region_name=region)
                            print("[INFO] Checking for required permissions to screenshot: {} on {} [INFO]" .format(instanceid, region))
                            response = client.get_console_screenshot(DryRun=True, InstanceId=instanceid,WakeUp=True)
                        except botocore.exceptions.ClientError as e:
                            if e.response['Error']['Code'] == 'DryRunOperation':
                                print('[+] {} : Has permissions...proceeding with the screenshot attempt [+]' .format(AWS_ACCESS_KEY_ID))
                                response = client.get_console_screenshot(DryRun=False, InstanceId=instanceid,WakeUp=True)
                                print('[+] Writing screenshot to screenshots/{}.png [+]'.format(instanceid))
                                file = open('{}/screenshots/{}.png'.format(os.getcwd(),instanceid), "wb")
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


def get_console_screenshot_all_region_list(file,region):
    try:
        client = boto3.client('ec2', region_name=region)

        alist = [line.rstrip() for line in open(file)]
        for line in alist:
            try:
                print("[INFO] Checking for required permissions to screenshot: {} on {} [INFO]" .format(line, region))
                response = client.get_console_screenshot(DryRun=True, InstanceId=line,WakeUp=True)
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'DryRunOperation':
                    print('[+] {} : Has permissions...proceeding with the screenshot attempt [+]' .format(AWS_ACCESS_KEY_ID))
                    response = client.get_console_screenshot(DryRun=False, InstanceId=line,WakeUp=True)
                    print('[+] Writing screenshot to screenshots/{}.png [+]'.format(line))
                    file = open('{}/screenshots/{}.png'.format(os.getcwd(),line), "wb")
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
            file = open('{}/loot/{}-console.txt'.format(os.getcwd(),instanceid), "w")
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
    try:
        for region in regions:
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
                        try:
                            client = boto3.client('ec2', region_name=region)
                            print("[INFO] Checking for required permissions to get console output: {} on {} [INFO]" .format(instanceid, region))
                            response = client.get_console_output(DryRun=True, InstanceId=instanceid)
                        except botocore.exceptions.ClientError as e:
                            if e.response['Error']['Code'] == 'DryRunOperation':
                                print('[+] {} : Has permissions...proceeding with the console output attempt [+]' .format(AWS_ACCESS_KEY_ID))
                                response = client.get_console_output(DryRun=False, InstanceId=instanceid)
                                print('[+] Writing console output to loot/{}-console.txt [+]'.format(instanceid))
                                file = open('{}/loot/{}-console.txt'.format(os.getcwd(),instanceid), "w")
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
                        try:
                            client = boto3.client('ec2', region_name=region)
                            print("[INFO] Checking for required permissions to get console output: {} on {} [INFO]" .format(instanceid, region))
                            response = client.get_console_output(DryRun=True, InstanceId=instanceid)
                        except botocore.exceptions.ClientError as e:
                            if e.response['Error']['Code'] == 'DryRunOperation':
                                print('[+] {} : Has permissions...proceeding with the console output attempt [+]' .format(AWS_ACCESS_KEY_ID))
                                response = client.get_console_output(DryRun=False, InstanceId=instanceid)
                                print('[+] Writing console output to loot/{}-console.txt [+]'.format(instanceid))
                                file = open('{}/loot/{}-console.txt'.format(os.getcwd(),instanceid), "w")
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


def get_console_output_all_region_list(file,region):
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
                    file = open('{}/loot/{}-console.txt'.format(os.getcwd(),line), "w")
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
