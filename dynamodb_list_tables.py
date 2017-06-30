'''
dynamoDB examples
'''

import boto3
import botocore

import json
import urllib
import logging
import sys,os
import pprint

pp = pprint.PrettyPrinter(indent=5, width=80)

from libs.dynamodb import *

AWS_ACCESS_KEY_ID = ''
AWS_SECRET_ACCESS_KEY = ''


list_dynamodb_tables(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
list_dynamodb_tables_detailed(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)