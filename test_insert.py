import builtins
import datetime
import sqlite3
from sqlite3 import Error

from  libs.sql import *

# Provides us with a global var "db_name" we can access anywhere
builtins.db_name = "weirdAAL.db"
target = "sometarget"

#create some tables to stick data in

if __name__ == "__main__":
    timenow = datetime.datetime.now()

    test_aws_key = [("AKIAIOSFODNN7EXAMPLE", "some test shit", target)]
    insert_awskey_data(db_name,test_aws_key)

    test_service_data = [("ec2","DescribeInstances","AKIAIOSFODNN7EXAMPLE", target, timenow),("ecr","DescribeRepositories","AKIAIOSFODNN7EXAMPLE", target, timenow)]
    insert_reconservice_data(db_name, test_service_data)

    test_sub_service_data = [("ec2","DescribeInstances","{'Groups': [], 'Instances': [{'AmiLaunchIndex': 0, 'ImageId': 'ami-90123455', 'InstanceId': 'i-04340cXXXXXXX', 'InstanceType': 't2.micro', 'KeyName': 'TEST THAT SHIT', 'LaunchTime': datetime.datetime(2018, 3, 28, 15, 42, 9, tzinfo=tzutc()), 'Monitoring': {'State': 'disabled'}, 'Placement': {'AvailabilityZone': 'us-east-1e', 'GroupName': '', 'Tenancy': 'default'}, 'Platform': 'windows', 'PrivateDnsName': 'ip-192-168-1-15.ec2.internal', 'PrivateIpAddress': '192.168.1.15', 'ProductCodes': [], 'PublicDnsName': '', 'State': {'Code': 16, 'Name': 'running'}, 'StateTransitionReason': '', 'SubnetId': 'subnet-12345a', 'VpcId': 'vpc-12345a', 'Architecture': 'x86_64', 'BlockDeviceMappings': [{'DeviceName': '/dev/sda1', 'Ebs': {'AttachTime': datetime.datetime(2018, 3, 28, 15, 42, 9, tzinfo=tzutc()), 'DeleteOnTermination': True, 'Status': 'attached', 'VolumeId': 'vol-123456'}}], 'ClientToken': '', 'EbsOptimized': False, 'EnaSupport': True, 'Hypervisor': 'xen', 'NetworkInterfaces': [{'Attachment': {'AttachTime': datetime.datetime(2018, 3, 28, 15, 42, 9, tzinfo=tzutc()), 'AttachmentId': 'eni-attach-12345', 'DeleteOnTermination': True, 'DeviceIndex': 0, 'Status': 'attached'}, 'Description': 'Primary network interface', 'Groups': [{'GroupName': 'INTERNAL', 'GroupId': 'sg-x12345c'}], 'Ipv6Addresses': [], 'MacAddress': 'ff:aa:ad:b1:c0:34', 'NetworkInterfaceId': 'eni-654321', 'OwnerId': 'xxxxxxxxxx', 'PrivateIpAddress': '192.168.1.15', 'PrivateIpAddresses': [{'Primary': True, 'PrivateIpAddress': '192.168.1.15'}], 'SourceDestCheck': True, 'Status': 'in-use', 'SubnetId': 'subnet-85d385ba', 'VpcId': 'vpc-deadbabe'}], 'RootDeviceName': '/dev/sda1', 'RootDeviceType': 'ebs', 'SecurityGroups': [{'GroupName': 'INTERNAL', 'GroupId': 'sg-12345'}], 'SourceDestCheck': True, 'Tags': [{'Key': 'Name', 'Value': 'INTERNAL'}], 'VirtualizationType': 'hvm'}], 'OwnerId': 'xxxxxxxxxx', 'ReservationId': 'r-00000000555555'}","AKIAIOSFODNN7EXAMPLE", target, datetime.datetime.now()),("ecr","DescribeRepositories","poop", "AKIAIOSFODNN7EXAMPLE", target, datetime.datetime.now())]
    insert_sub_service_data(db_name, test_sub_service_data)
