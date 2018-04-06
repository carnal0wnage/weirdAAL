import sys
from libs.s3 import *
from config import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY

if len(sys.argv) < 2:
    print("must specify bucket: {} <bucketname>".format(sys.argv[0]))
    sys.exit(-1)

#Attempt to list the contents of the bucket
get_s3bucket_policy(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, sys.argv[1])
