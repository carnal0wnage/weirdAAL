'''
ECR functions
'''

from libs.aws.ecr import *


def module_ecr_describe_repos():
    '''
    Describe ECR repositories
    python3 weirdAAL.py -m ecr_describe_repos -t demo
    '''
    ecr_describe_repositories()
