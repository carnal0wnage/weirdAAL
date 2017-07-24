'''
example calling cloudwatch functions
decribe alarms, describe alarm history, list metrics
'''
from libs.cloudwatch import *
from config import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY

describe_alarms(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
describe_alarm_history(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
list_metrics(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
