'''
This file is used to list volumes of ec2 instances
'''
from libs.ec2 import *
from config import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY

get_instance_volume_details(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
get_instance_volume_details2(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
