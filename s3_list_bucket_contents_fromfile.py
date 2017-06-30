import boto3
import botocore

import json
import urllib
import logging
import sys,os
import pprint

pp = pprint.PrettyPrinter(indent=5, width=80)

from libs.s3 import *

AWS_ACCESS_KEY_ID = ''
AWS_SECRET_ACCESS_KEY =''


#open a list of possible buckets and attempt to list the contents
f = open('test.txt', 'r')
for line in f:
    line = line.strip()
    if not line:
        continue
    else:
        get_s3bucket_policy(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY,line)
