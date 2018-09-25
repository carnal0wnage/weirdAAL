'''
dynamoDBstreams examples
'''
from libs.aws.dynamodbstreams import *


def module_dynamodbstreams_list_streams():
    '''
    List dynamodbstream streams
    python3 weirdAAL.py -m dynamodbstreams_list_streams -t demo
    '''
    list_dynamodbstreams()
