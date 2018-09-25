'''
This file is used to perform some EMR actions
'''

from libs.aws.emr import *


def module_emr_list_clusters():
    '''
    EMR List Clusters
    python3 weirdAAL.py -m emr_list_clusters -t demo
    '''
    list_clusters()


def module_emr_list_security_configurations():
    '''
    EMR List Security Configuration
    python3 weirdAAL.py -m emr_list_security_configurations -t demo
    '''
    list_security_configurations()
