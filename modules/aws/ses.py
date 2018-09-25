'''
SES module
'''

from libs.aws.ses import *


def module_ses_list_identities():
    '''
    SES List identities

    python3 weirdAAL.py -m ses_list_identities -t demo
    '''
    list_identities()


def module_ses_get_send_statistics():
    '''
    SES  get send statistics

    python3 weirdAAL.py -m ses_get_send_statistics -t demo
    '''
    get_send_statistics()


def module_ses_list_configuration_sets():
    '''
    SES list configuration sets

    python3 weirdAAL.py -m ses_list_configuration_sets -t demo
    '''
    list_configuration_sets()
