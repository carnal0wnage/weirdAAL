'''
This file is used to perform some EMR actions
'''

import boto3
import botocore

import json
import urllib
import logging
import sys,os
import pprint

pp = pprint.PrettyPrinter(indent=5, width=80)

from libs.emr import *

#insert AWS key, will figure out how to pull this in from a single file for all scripts

AWS_ACCESS_KEY_ID = ''
AWS_SECRET_ACCESS_KEY = ''



list_clusters(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
list_security_configurations(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
