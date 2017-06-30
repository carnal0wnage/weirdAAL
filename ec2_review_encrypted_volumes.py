
'''
This file is used to list EBS volumes and whether or not they are encrypted. This is only for "in-use" (running) volumes.
'''

import boto3
import botocore

import json
import urllib
import logging
import sys,os
import pprint

pp = pprint.PrettyPrinter(indent=5, width=80)

from libs.ec2 import *

#insert AWS key, will figure out how to pull this in from a single file for all scripts

AWS_ACCESS_KEY_ID = ''
AWS_SECRET_ACCESS_KEY = ''

review_encrypted_volumes(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
