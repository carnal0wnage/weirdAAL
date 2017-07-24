from libs.opsworks import *
from config import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY

describe_stacks(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
