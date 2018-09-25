'''
Module for interacting with the lightsail
'''

from libs.aws.lightsail import *


def module_lightsail_get_instances():
    '''
    Lightsail get_instances
    python3 weirdAAL.py -m lightsail_get_instances -t demo
    '''
    lightsail_get_instances()
