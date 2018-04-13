'''
This file is used to perform various pricing operations
usually have to be root or be specifically assigned the
permission to get anything from this
'''

from libs.pricing import *
from config import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY


def step_pricing_describe_services():
    pricing_describe_services(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
