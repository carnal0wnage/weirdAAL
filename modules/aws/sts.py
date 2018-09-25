'''
This file is used to perform some EMR actions
'''

from libs.aws.sts import *


def module_sts_get_accountid():
    '''
    STS get account ID - just ID

    python3 weirdAAL.py -m sts_get_accountid -t demo
    '''
    sts_get_accountid()


def module_sts_get_accountid_all():
    '''
    STS get as much info as possible - prints AccountID, UserID, ARN

    python3 weirdAAL.py -m sts_get_accountid_all -t demo
    '''
    sts_get_accountid_all()
