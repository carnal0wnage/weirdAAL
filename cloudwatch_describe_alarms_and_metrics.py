'''
example calling cloudwatch functions
decribe alarms, describe alarm history, list metrics
'''

import boto3
import botocore

import json
import urllib
import logging
import sys,os
import pprint

pp = pprint.PrettyPrinter(indent=5, width=80)

from libs.cloudwatch import *

AWS_ACCESS_KEY_ID = ''
AWS_SECRET_ACCESS_KEY = ''


describe_alarms(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
describe_alarm_history(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
list_metrics(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)