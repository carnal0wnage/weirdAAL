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

def step_iam_check_root_account():
	check_root_account(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)

def step_iam_get_password_policy():
	get_password_policy(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)

def step_iam_list_roles():
	iam_list_roles(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)

def step_iam_list_policies():
	iam_list_policies(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)

#have to figure out the argument passing part here first
def step_iam_list_user_policies():
	iam_list_user_policies(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, 'root')

def step_iam_list_attached_user_policies():
	iam_list_attached_user_policies(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, 'root')

def step_iam_list_entities_for_policy():
	iam_list_entities_for_policy(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, 'arn:aws:iam::xxxxxxx')
