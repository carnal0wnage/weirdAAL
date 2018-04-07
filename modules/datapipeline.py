'''
data pipeline example
'''
from libs.datapipeline import *
from config import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY

def step_datapipeline_list_pipelines():
    list_pipelines(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
