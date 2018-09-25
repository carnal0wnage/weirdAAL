'''
datapipeline modules
'''

from libs.aws.datapipeline import *


def module_datapipeline_list_pipelines():
    '''
    List DataPileLine pipelines
    python3 weirdAAL.py -m datapipeline_list_pipelines -t demo
    '''
    datapipeline_list_pipelines()
