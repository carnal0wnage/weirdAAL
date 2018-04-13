'''
Firehose functions
'''
from  libs.firehose import *

from config import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY


def step_firehose_list_delivery_streams():
	firehose_list_delivery_streams(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)


def step_firehose_describe_delivery_streams():
	firehose_describe_delivery_streams(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)