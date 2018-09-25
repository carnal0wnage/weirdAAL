'''
IAM recon functions
'''

from libs.aws.iam import *


def module_iam_list_groups():
    '''
    Lists the IAM groups.
    python3 weirdAAL.py -m iam_list_groups -t yolo
    '''
    iam_list_groups()


def module_iam_get_user():
    '''
    Retrieves information about the specified IAM user, including the user's creation date, path, unique ID, and ARN.
    python3 weirdAAL.py -m iam_get_user -t yolo
    '''
    iam_get_user()


def module_iam_get_account_summary():
    '''
    Retrieves information about IAM entity usage and IAM quotas in the AWS account
    python3 weirdAAL.py -m iam_get_account_summary -t yolo
    '''
    iam_get_account_summary()


def module_iam_list_users():
    '''
    Lists the IAM users that have the specified path prefix. If no path prefix is specified, the operation returns all users in the AWS account. If there are none, the operation returns an empty list.
    python3 weirdAAL.py -m iam_list_users -t yolo
    '''
    iam_list_users()


def module_iam_check_root_account():
    '''
    Attempts to call a few IAM functions to see if the account has root or IAM [elevated] permissions
    python3 weirdAAL.py -m iam_check_root_account -t yolo
    '''
    check_root_account()


def module_iam_get_password_policy():
    '''
    Retrieves the password policy for the AWS account.
    python3 weirdAAL.py -m iam_get_password_policy -t yolo
    '''
    get_password_policy()


def module_iam_list_roles():
    '''
    Lists the IAM roles that have the specified path prefix. If there are none, the operation returns an empty list.
    python3 weirdAAL.py -m iam_list_roles -t yolo
    '''
    iam_list_roles()

def module_iam_list_roles_assumable():
    '''
    Lists the IAM roles that have the specified path prefix that are assumable by AWS principals and excludes roles assumable by AWS services. If there are none, the operation returns an empty list.
    python3 weirdAAL.py -m iam_list_roles_assumable -t yolo
    '''
    iam_list_roles_assumable()

def module_iam_list_policies():
    '''
    Lists all the managed policies that are available in your AWS account, including your own customer-defined managed policies and all AWS managed policies.
    python3 weirdAAL.py -m iam_list_policies -t yolo
    '''
    iam_list_policies()


def module_iam_list_policies_attached():
    '''
    Lists all the managed policies that are available in your AWS account, including your own customer-defined managed policies and all AWS managed policies.
    adds the OnlyAttached=True flag (you probably want to run this one to see what's actually applied to the account)
    python3 weirdAAL.py -m iam_list_policies_attached -t yolo
    '''
    iam_list_policies_attached()


def module_iam_list_user_policies(*text):
    '''
    Lists the names of the inline policies embedded in the specified IAM user.
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


def module_iam_get_account_authorization_details():
    '''
    Retrieves information about all IAM users, groups, roles, and policies in your AWS account, including their relationships to one another. Use this API to obtain a snapshot of the configuration of IAM permissions (users, groups, roles, and policies) in your account.
    python3 weirdAAL.py -m iam_get_account_authorization_details -t yolo
    '''
    get_account_authorization_details()
