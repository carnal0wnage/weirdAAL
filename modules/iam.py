'''
IAM recon functions
'''
from  libs.iam import *

from config import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY


def step_iam_list_groups():
    iam_list_groups(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)


def step_iam_get_user():
    iam_get_user(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)


def step_iam_get_account_summary():
    iam_get_account_summary(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)


def step_iam_list_users():
    iam_list_users(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)