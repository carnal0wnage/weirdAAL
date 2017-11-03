# This file will help to serve as a starting point for using the rest of the tools
# Things we want to figure out
# 1) Is your key active?
# 2) If active, can you read monitoring configs, can you write?
# 3) Okay, you can read monitoring configs. We recommend things to avoid. Want to go further? Use write access to disable (if applicable)
# 4) Don't want to do anything with monitoring? That's fine, let's guide you through figuring out what your access looks like
# 5) Help with a printout of options from this point forward

import boto3
import argparse

import argparse
parser = argparse.ArgumentParser()
parser.add_argument("-v", "--verbosity", help="increase output verbosity",
action="store_true")
args = parser.parse_args()

if (args.verbosity):
    print("Verbosity is enabled")
