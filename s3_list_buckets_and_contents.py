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

get_s3objects_for_account_detailed(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
