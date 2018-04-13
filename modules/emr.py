'''
This file is used to perform some EMR actions
'''
from libs.emr import *
from config import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY


def step_emr_list_clusters():
    list_clusters(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)


def step_emr_list_security_configurations():
    list_security_configurations(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
