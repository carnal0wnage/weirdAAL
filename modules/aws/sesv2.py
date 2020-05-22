'''
SESv2 module
'''

from libs.aws.sesv2 import *


def module_sesv2_list_email_identities():
    '''
    SES List Email Identities

    python3 weirdAAL.py -m sesv2_list_email_identities -t demo
    '''
    list_email_identities()