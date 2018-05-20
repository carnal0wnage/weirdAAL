'''
SNS module
'''

from libs.sns import *

def module_sns_list_topics():
    '''
    SNS list all topics
    python3 weirdAAL.py -m sns_list_topics -t demo
    '''
    list_sns_topics()

def module_sns_list_subscribers(*args):
    '''
    SNS list subscribers for a topic. Takes two arguments - the topic arn and then the region.
    python3 weirdAAL.py -m sns_list_subscribers -a arn:aws:sns:us-east-1:123456789123:sometopic,us-east-1
    '''
    try:
        if args[0][0] and args[0][1]:
            list_sns_subscribers(args[0][0], args[0][1])
    except IndexError:
        print("Please provide a topic arn *AND* region, ex: -a arn:aws:sns:us-east-1:123456789123:sometopic,us-east-1")

def module_sns_delete_topic(*args):
    '''
    SNS delete a topic. Takes two arguments - the topic arn and the region.
    python3 weirdAAL.py -m sns_delete_topic -a arn:aws:sns:us-east-1:123456789123:sometopic,us-east-1
    '''
    try:
        if args[0][0] and args[0][1]:
            delete_sns_topic(args[0][0], args[0][1])
    except IndexError:
        print("Please provide a topic arn *AND* region, ex: -a arn:aws:sns:us-east-1:123456789123:sometopic,us-east-1")
