'''
dynamoDB examples
'''
from libs.dynamodb import *
from config import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY

list_dynamodb_tables(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
list_dynamodb_tables_detailed(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
