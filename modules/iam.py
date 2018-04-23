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


def module_iam_list_users():
    iam_list_users()

def module_iam_check_root_account():
	check_root_account()

def module_iam_get_password_policy():
	get_password_policy()

def module_iam_list_roles():
	iam_list_roles()

def module_iam_list_policies():
	iam_list_policies()


def module_iam_list_user_policies(*text):
	'''
	List user policies for specified user
	python3 weirdAAL.py -m iam_list_user_policies -a python -t yolo
	'''
	iam_list_user_policies(text[0][0])

def module_iam_list_attached_user_policies(*text):
	'''
	List attached user policies for specified user
	python3 weirdAAL.py -m iam_list_attached_user_policies -a python -t yolo
	'''
	iam_list_attached_user_policies(text[0][0])

def module_iam_list_entities_for_policy(*text):
	'''
	 python3 weirdAAL.py -m iam_list_entities_for_policy -a 'arn:aws:iam::...' -t yolo
	'''
	iam_list_entities_for_policy(text[0][0])
