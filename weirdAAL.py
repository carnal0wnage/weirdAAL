#!/usr/bin/env python3
# This file will help to serve as a starting point for using the rest of the tools
# Things we want to figure out
# 1) Is your key active?
# 2) If active, can you read monitoring configs, can you write?
# 3) Okay, you can read monitoring configs. We recommend things to avoid. Want to go further? Use write access to disable (if applicable)
# 4) Don't want to do anything with monitoring? That's fine, let's guide you through figuring out what your access looks like
# 5) Help with a printout of options from this point forward

import boto3
import argparse
import os
from botocore.exceptions import ClientError

AWS_ACCESS_KEY_ID=os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY=os.getenv("AWS_SECRET_ACCESS_KEY")

parser = argparse.ArgumentParser()
parser.add_argument("-s", "--step", help="list the step you would like to run",
action="store", type=int, required=True)
parser.add_argument("-v", "--verbosity", help="increase output verbosity",
action="store_true")
args = parser.parse_args()

def perform_credential_check():
    try:
        client = boto3.client("sts", aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
        account_id = client.get_caller_identity()["Account"]
    except ClientError as e:
        print("The AWS Access Keys are not valid/active")
        exit(1)

# Need to figure out if we have keys in the ENV or not
if AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY:
    perform_credential_check()
else:
    print("Please supply keys as outlined in our README.md file")
    exit(1)

# We need the user to tell us the step they want to proceed on
if (args.step == 1):
    print("Beginning step 1")
elif (args.step == 2):
    print("Beginning step 2")
elif (args.step == 3):
    print("Beginning step 3")
else:
    print("We need a valid step to continue...")


# Allow the user to specify verbosity for debugging
if (args.verbosity):
    print("Verbosity is enabled")
