'''
This file is used to perform various EC2 operations
'''
from libs.ec2 import *
from config import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY

'''
Basic info about each instance
'''


def step_ec2_get_instances_basic():
    get_instance_details_basic(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)


'''
All info about each instance
'''


def step_ec2_get_instances_detailed():
    get_instance_details(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)


'''
show volumes sorted by instanceId ex: instanceID-->multiple volumes  less detail than get_instance_volume_details2
'''


def step_ec2_get_instance_volume_details():
    get_instance_volume_details(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)


'''
show volumes by instanceId but instanceID->volume1 of ID, instanceID->volume2 of ID but more details.
'''


def step_ec2_get_instance_volume_details2():
    get_instance_volume_details2(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
