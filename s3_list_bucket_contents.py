import boto3
import botocore

import json
import urllib
import logging
import sys,os
import pprint

pp = pprint.PrettyPrinter(indent=5, width=80)

from libs.s3 import *
from config import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY

#Attempt to list the contents of the bucket
get_s3bucket_policy(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY,'myfuckingbucket')
