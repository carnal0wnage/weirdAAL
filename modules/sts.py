'''
This file is used to perform some EMR actions
'''
from libs.sts import *
from config import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY


def step_sts_get_accountid():
    get_accountid(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)

def step_sts_get_accountidall():
    get_accountid_all(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)