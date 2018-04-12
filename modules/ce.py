'''
This file is used to perform various Cost Explorer operations
usually have to be root or be specifically assigned the
permission to get anything from this
'''

from libs.ce import *
from config import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY


def step_cost_explorer_get_cost_and_usage():
    ce_get_cost_and_usage(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)