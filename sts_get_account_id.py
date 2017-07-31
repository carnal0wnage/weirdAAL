'''
This file is used to perform some EMR actions
'''
from libs.sts import *
from config import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY

get_accountid(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
get_accountid_all(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)