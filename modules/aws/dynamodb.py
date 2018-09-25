'''
dynamoDB examples
'''
from libs.aws.dynamodb import *


def module_dynamodb_list_tables():
    '''
    DynamoDB list tables
    python3 weirdAAL.py -m dynamodb_list_tables -t demo
    '''
    list_dynamodb_tables()


def module_dynamodb_list_tables_detailed():
    '''
    DynamoDB list tables detailed - also tries decribe_tables on each table
    python3 weirdAAL.py -m dynamodb_list_tables_detailed -t demo
    '''
    list_dynamodb_tables_detailed()
