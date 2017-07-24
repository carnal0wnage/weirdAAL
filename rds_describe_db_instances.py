from libs.rds import *
from config import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY

describe_db_instances(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
