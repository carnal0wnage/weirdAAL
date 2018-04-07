'''
dynamoDBstreams examples
'''
from libs.dynamodbstreams import *
from config import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY

def step_dynamodbstreams_list_streams():
    list_dynamodbstreams(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)