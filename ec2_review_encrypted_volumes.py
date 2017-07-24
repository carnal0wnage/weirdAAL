
'''
This file is used to list EBS volumes and whether or not they are encrypted. This is only for "in-use" (running) volumes.
'''
from libs.ec2 import *
from config import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY

review_encrypted_volumes(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
