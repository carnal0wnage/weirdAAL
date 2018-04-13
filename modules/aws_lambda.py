'''
This file is used to list lambda functions and event mappings
'''
from libs.aws_lambda import *
from config import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY


def step_lambda_list_functions():
    list_functions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)


def step_lambda_list_event_source_mappings():
    list_event_source_mappings(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
