'''
IAM recon functions
'''
from  libs.iam import *


def module_iam_list_groups():
    iam_list_groups()


def module_iam_get_user():
    iam_get_user()


def module_iam_get_account_summary():
    iam_get_account_summary()


def module_iam_list_users(*args):
    iam_list_users()

def module_iam_check_root_account():
	check_root_account()

def module_iam_get_password_policy():
	get_password_policy()

def module_iam_list_roles():
	iam_list_roles()

def module_iam_list_policies():
	iam_list_policies()

#have to figure out the argument passing part here first
def module_iam_list_user_policies():
	iam_list_user_policies( 'root')

def module_iam_list_attached_user_policies():
	iam_list_attached_user_policies( 'root')

def module_iam_list_entities_for_policy():
	iam_list_entities_for_policy('arn:aws:iam::xxxxxxx')
