'''
This file is used to perform various EC2 operations
'''

from libs.ec2 import *

'''
Basic info about each EC2 instance
ex:
[+] Listing instances for region: us-west-2 [+]
InstanceID: i-XXXXXXXXXXXXXXX, InstanceType: t2.micro, State: {'Code': 80, 'Name': 'stopped'}, Launchtime: 2016-08-25 22:31:31+00:00
'''


def step_ec2_get_instances_basic():
    get_instance_details_basic()


'''
All info about each EC2 instance
'''


def step_ec2_get_instances_detailed():
    get_instance_details()


'''
show volumes sorted by instanceId ex: instanceID-->multiple volumes  less detail than get_instance_volume_details2
'''


def step_ec2_get_instance_volume_details():
    get_instance_volume_details()


'''
show volumes by instanceId but instanceID->volume1 of ID, instanceID->volume2 of ID but more details.
'''


def step_ec2_get_instance_volume_details2():
    get_instance_volume_details2()


'''
This function is used to list EBS volumes and whether or not they are encrypted. This is only for "in-use" (running) volumes.
'''


def step_ec2_review_encrypted_volumes():
    review_encrypted_volumes()

'''
This function is used to describe ec2 network addresses.
'''


def step_ec2_describe_addresses():
    describe_addresses()

'''
This function is used to describe ec2 network interfaces.
'''

def step_ec2_describe_network_interfaces():
    describe_network_interfaces()


def step_ec2_describe_route_tables():
    describe_route_tables()
