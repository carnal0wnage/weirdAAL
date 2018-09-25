'''
This file is used to perform cloudtrail actions
'''
from libs.aws.cloudtrail import *


def module_cloudtrail_describe_trails():
    '''
    Describe CloudTrail trails
    python3 weirdAAL.py -m cloudtrail_describe_trails -t demo
    '''
    describe_trails()


def module_cloudtrail_list_public_keys():
    '''
    List public keys associated with the CloudTrail account
    python3 weirdAAL.py -m cloudtrail_list_public_keys -t demo
    '''
    list_public_keys()


def module_cloudtrail_stop_trail(TrailARN):
    '''
    Stop a specified CloudTrail ARN
    python3 weirdAAL.py -m cloudtrail_stop_trail -a arn:aws:cloudtrail:us-east-1... -t demo
    '''
    stop_trail(TrailARN)


def module_cloudtrail_delete_trail(TrailARN):
    '''
    Delete a specified CloudTrail ARN
    python3 weirdAAL.py -m cloudtrail_delete_trail -a arn:aws:cloudtrail:us-east-1... -t demo
    '''
    delete_trail(TrailARN)
