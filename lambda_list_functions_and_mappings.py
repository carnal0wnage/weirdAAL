'''
This file is used to list lambda functions and event mappings
'''

import boto3
import botocore

import json
import urllib
import logging
import sys,os
import pprint

pp = pprint.PrettyPrinter(indent=5, width=80)

from libs.aws_lambda import *
from config import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY

list_functions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
list_event_source_mappings(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
