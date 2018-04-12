'''
This file is used to perform cloudtrail actions
'''
from libs.cloudtrail import *
from config import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY


def step_cloudtrail_describe_trails():
    describe_trails(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)


def step_cloudtrail_list_public_keys():
    list_public_keys(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)