'''
example calling cloudwatch functions
decribe alarms, describe alarm history, list metrics
'''
from libs.cloudwatch import *


def module_cloudwatch_describe_alarms():
    describe_alarms()

def module_cloudwatch_describe_alarm_history():
    describe_alarm_history()

def module_cloudwatch_list_metrics():
    list_metrics()
