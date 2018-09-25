'''
This file is used to perform various Cost Explorer operations
usually have to be root or be specifically assigned the
permission to get anything from this
'''

from libs.aws.ce import *


def module_costexplorer_get_cost_and_usage():
    '''
    Attempt to list cost and usage via the Cost Explorer service
    python3 weirdAAL.py -m costexplorer_get_cost_and_usage -t demo
    '''
    ce_get_cost_and_usage()
