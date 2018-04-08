'''
SQS
'''
from libs.sqs import *
from config import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY


def step_sqs_list_queues():
	sqs_list_queues(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
