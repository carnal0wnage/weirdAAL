'''
Firehose functions
'''
from libs.aws.firehose import *


def module_firehose_list_delivery_streams():
    '''
    Firehose list delivery streams
    python3 weirdAAL.py -m firehose_list_delivery_streams -t demo
    '''
    firehose_list_delivery_streams()


def module_firehose_describe_delivery_streams():
    '''
    Firehose describe delivery streams
    python3 weirdAAL.py -m firehose_describe_delivery_streams -t demo
    '''
    firehose_describe_delivery_streams()
