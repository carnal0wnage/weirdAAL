'''
example calling cloudwatch functions
decribe alarms, describe alarm history, list metrics
'''
from libs.aws.cloudwatch import *


def module_cloudwatch_describe_alarms():
    '''
    Describe CloudWatch Alarms
    python3 weirdAAL.py -m cloudwatch_describe_alarms -t demo
    '''
    cloudwatch_describe_alarms()


def module_cloudwatch_describe_alarm_history():
    '''
    Describe CloudWatch Alarm History
    python3 weirdAAL.py -m cloudwatch_describe_alarm_history -t demo
    '''
    cloudwatch_describe_alarm_history()


def module_cloudwatch_list_metrics():
    '''
    CloudWatch List Metrics
    python3 weirdAAL.py -m cloudwatch_list_metrics -t demo
    '''
    cloudwatch_list_metrics()
