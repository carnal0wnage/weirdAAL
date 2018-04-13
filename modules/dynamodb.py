'''
dynamoDB examples
'''
from libs.dynamodb import *
from config import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY

def step_dynamodb_list_tables():
    list_dynamodb_tables(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)

def step_dynamodb_list_tables_detailed():
    list_dynamodb_tables_detailed(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
