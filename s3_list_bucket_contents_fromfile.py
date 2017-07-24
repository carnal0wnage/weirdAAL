from libs.s3 import *
from config import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY

#open a list of possible buckets and attempt to list the contents
with open('bucket_list.txt', 'r') as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        else:
            get_s3bucket_policy(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, line)
