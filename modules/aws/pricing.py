'''
This file is used to perform various pricing operations
usually have to be root or be specifically assigned the
permission to get anything from this
'''

from libs.aws.pricing import *


def module_pricing_describe_services():
    '''
    Pricing describe services
    python3 weirdAAL.py -m pricing_describe_services -t yolo
    '''
    pricing_describe_services()
