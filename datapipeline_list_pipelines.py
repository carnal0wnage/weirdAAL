'''
data pipeline example
'''
from libs.datapipeline import *
from config import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY


list_pipelines(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
