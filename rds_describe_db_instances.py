import boto3
import botocore

import json
import urllib
import logging
import sys,os
import pprint

from libs.rds import *

pp = pprint.PrettyPrinter(indent=5, width=80)

#insert AWS key, will figure out how to pull this in from a single file for all scripts

#AWS_ACCESS_KEY_ID = ''
#AWS_SECRET_ACCESS_KEY =''

describe_db_instances(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
