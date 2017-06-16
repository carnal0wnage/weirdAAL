import boto3
import botocore

import json
import urllib
import logging
import sys,os
import pprint

pp = pprint.PrettyPrinter(indent=5, width=80)

from brute.brute import *

#insert AWS key, will figure out how to pull this in from a single file for all scripts

AWS_ACCESS_KEY_ID = ''
AWS_SECRET_ACCESS_KEY =''

#brute_acm_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
#brute_apigateway_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
#brute_appstream_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
#brute_athena_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
brute_batch_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
#brute_budgets_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
#brute_autoscaling_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
#brute_cloudformation_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
#brute_cloudfront_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
#brute_cloudhsm_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
#brute_ec2_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
#brute_elasticbeanstalk_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
#brute_lambda_permissions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)