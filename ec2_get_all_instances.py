'''
This file is used to list ec2 instances
'''
from libs.ec2 import *
from config import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY

get_instance_details(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
