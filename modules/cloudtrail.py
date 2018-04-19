'''
This file is used to perform cloudtrail actions
'''
from libs.cloudtrail import *


def module_cloudtrail_describe_trails():
    describe_trails()


def module_cloudtrail_list_public_keys():
    list_public_keys()


def module_cloudtrail_stop_trail(TrailARN):
    stop_trail(TrailARN)


def module_cloudtrail_delete_trail(TrailARN):
    delete_trail(TrailARN)