'''
SQS Modules
'''

from libs.aws.sqs import *


def module_sqs_list_queues():
    '''
    SQS List Queues

    python3 weirdAAL.py -m sqs_list_queues -t demo
    '''
    sqs_list_queues()
