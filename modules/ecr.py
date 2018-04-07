'''
ECR functions
'''
from  libs.ecr import *

from config import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY

def step_ecr_describe_repos():
	describe_repositories(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
