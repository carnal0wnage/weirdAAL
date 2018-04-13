'''
rds module
'''


from libs.rds import *
from config import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY

def step_rds_describe_db_instances():
     describe_db_instances(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
