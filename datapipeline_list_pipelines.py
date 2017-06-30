'''
data pipeline example
'''

import boto3
import botocore

import json
import urllib
import logging
import sys,os
import pprint

pp = pprint.PrettyPrinter(indent=5, width=80)

from libs.datapipeline import *

AWS_ACCESS_KEY_ID = ''
AWS_SECRET_ACCESS_KEY = ''


list_pipelines(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)