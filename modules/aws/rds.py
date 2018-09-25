'''
RDS module
'''

from libs.aws.rds import *


def module_rds_describe_db_instances():
    '''
    RDS Describe Instances
    python3 weirdAAL.py -m rds_describe_db_instances -t yolo
    '''
    describe_db_instances()
