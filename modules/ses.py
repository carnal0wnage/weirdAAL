'''
SES module
'''


from libs.ses import *
from config import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY

def step_ses_list_identities():
     list_identities(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)

def step_ses_get_send_statistics():
     get_send_statistics(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)

def step_ses_list_configuration_sets():
     list_configuration_sets(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)