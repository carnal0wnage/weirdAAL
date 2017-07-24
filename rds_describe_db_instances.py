import boto3
import botocore

import json
import urllib
import logging
import sys,os
import pprint

from libs.rds import *
from config import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY

pp = pprint.PrettyPrinter(indent=5, width=80)

describe_db_instances(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
