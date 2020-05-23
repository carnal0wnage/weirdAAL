'''
S3 functions for WeirdAAL
'''

import boto3
import botocore
import os
import pprint
import sys

pp = pprint.PrettyPrinter(indent=5, width=80)

'''
Code to get the AWS_ACCESS_KEY_ID from boto3
'''
session = boto3.Session()
credentials = session.get_credentials()
AWS_ACCESS_KEY_ID = credentials.access_key
AWS_SECRET_ACCESS_KEY = credentials.secret_key

# from http://docs.aws.amazon.com/general/latest/gr/rande.html
regions = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ca-central-1', 'ap-south-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3', 'ap-southeast-1', 'ap-southeast-2', 'cn-north-1', 'cn-northwest-1', 'eu-central-1', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'sa-east-1']

region = 'us-east-1'


def s3_get_bucket_policy(bucket):
    try:
        client = boto3.client('s3', region_name=region)
        print('\n#### Attempting to list s3 bucket contents and bucket Policy & ACL for {} ####'.format(bucket))

        try:
            for key in client.list_objects(Bucket=bucket)['Contents']:
                print(key['Key'])

            '''
            # Create a paginator to pull 1000 objects at a time
                paginator = client.get_paginator('list_objects')
                pageresponse = paginator.paginate(Bucket=thebucket)

                # PageResponse Holds 1000 objects at a time and will continue to repeat in chunks of 1000.
                for pageobject in pageresponse:
                    for file in pageobject["Contents"]:
                        print(file["Key"])
            '''
        except KeyError as e:
                print("Bucket: {} is empty".format(bucket))
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                print('{} : cant list s3 bucket [AccessDenied]' .format(AWS_ACCESS_KEY_ID))
            elif e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                print('%s: Has No S3 Policy!' % bucket['Name'])
            elif e.response['Error']['Code'] == 'AllAccessDisabled':
                print('{} : cant list s3 bucket [AllAccessDisabled]' .format(AWS_ACCESS_KEY_ID))
            else:
                print("Unexpected error: {}" .format(e))
        except KeyboardInterrupt:
            print("CTRL-C received, exiting...")

        try:
            policy = client.get_bucket_policy(Bucket=bucket)
            if policy:
                print(bucket + " Policy: ")
                pp.pprint(policy['Policy'])
                print("\n")
            else:
                print("no Policy found for: {}".format(bucket))
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                print('{} : cant list s3 bucket policy [AccessDenied]' .format(AWS_ACCESS_KEY_ID))
            elif e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                print('\n{}: Has No S3 Policy!' .format(bucket))
                print("\n")
            elif e.response['Error']['Code'] == 'AllAccessDisabled':
                print('{} : cant list s3 bucket policy [AllAccessDisabled]' .format(AWS_ACCESS_KEY_ID))
            elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
                print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
            else:
                print("Unexpected error: {}" .format(e))
        try:
            acl = client.get_bucket_acl(Bucket=bucket)
            if acl:
                print("{} ACL Grants: ".format(bucket))
                pp.pprint(acl['Grants'])
                print("\n")
            else:
                pass
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                print('{} : cant list s3 bucket acl [AccessDenied]' .format(AWS_ACCESS_KEY_ID))
            elif e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                print('{}: Has No S3 Policy!' .format(bucket))
                print("\n")
            elif e.response['Error']['Code'] == 'AllAccessDisabled':
                print('{} : cant list s3 bucket acl [AllAccessDisabled]' .format(AWS_ACCESS_KEY_ID))
            elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
                print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
            else:
                print("Unexpected error: {}" .format(e))

    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidClientTokenId':
            sys.exit("The AWS KEY IS INVALID. Exiting")
        elif e.response['Error']['Code'] == 'NotSignedUp':
            print('{} : doesnt have s3 access' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print("Unexpected error: {}" .format(e))
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")


def s3_list_bucket_contents(bucket):
    try:
        client = boto3.client('s3', region_name=region)
        print('\n#### Attempting to list s3 bucket contents for {} ####'.format(bucket))

        try:
            for key in client.list_objects(Bucket=bucket)['Contents']:
                print(key['Key'])

            '''
            # Create a paginator to pull 1000 objects at a time
                paginator = client.get_paginator('list_objects')
                pageresponse = paginator.paginate(Bucket=thebucket)

                # PageResponse Holds 1000 objects at a time and will continue to repeat in chunks of 1000.
                for pageobject in pageresponse:
                    for file in pageobject["Contents"]:
                        print(file["Key"])
            '''
        except KeyError as e:
                print("Bucket: {} is empty".format(bucket))
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'AccessDenied':
            print('{} : cant list s3 bucket [AccessDenied]'.format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'NoSuchBucketPolicy':
            print('%s: Has No S3 Policy!' % bucket['Name'])
        elif e.response['Error']['Code'] == 'AllAccessDisabled':
            print('{} : cant list s3 bucket [AllAccessDisabled]'.format(AWS_ACCESS_KEY_ID))
        else:
            print("Unexpected error: {}" .format(e))
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")


def get_s3object_acl(bucket, myfile, region):
    '''
    # specifically get the acl on a file in a buckeet

    '''
    try:
        client = boto3.client('s3', region_name=region)
        print('#### Trying to enumate s3 ACL for {}:{} ####\n '.format(bucket, myfile))
        acl = client.get_object_acl(Bucket=bucket, Key=myfile)
        print(acl)

    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidClientTokenId':
            sys.exit("The AWS KEY IS INVALID. Exiting")
        elif e.response['Error']['Code'] == 'NotSignedUp':
            print('{} : doesnt have s3 access' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print("Unexpected error: {}" .format(e))
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")


def s3_get_objects_for_account():
    '''
    list s3 buckets for an account
    '''
    try:
        client = boto3.resource('s3', region_name=region)

        print('#### Trying to list s3 buckets for {} ####\n '.format(AWS_ACCESS_KEY_ID))
        for bucket in client.buckets.all():
            print(bucket.name)

    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidClientTokenId':
            sys.exit("The AWS KEY IS INVALID. Exiting")
        elif e.response['Error']['Code'] == 'AccessDenied':
            print('{} : cant list s3 bucket policy [AccessDenied]' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'NotSignedUp':
            print('{} : doesnt have s3 access' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print("Unexpected error: {}" .format(e))
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")


def s3_get_objects_for_account_detailed():
    '''
    list s3 buckets for an account and their policy
    '''
    try:
        client = boto3.resource('s3', region_name=region)

        print('#### Trying to list s3 buckets for {} ####\n '.format(AWS_ACCESS_KEY_ID))
        for bucket in client.buckets.all():
            print(bucket.name)
            s3_get_bucket_policy(bucket.name)

    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidClientTokenId':
            sys.exit("The AWS KEY IS INVALID. Exiting")
        elif e.response['Error']['Code'] == 'NotSignedUp':
            print('{} : doesnt have s3 access' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print("Unexpected error: {}" .format(e))
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")


def s3_get_bucket_objects_from_file(file):
    '''
    For a list of buckets attempt to list their contents
    '''
    try:
        client = boto3.resource('s3', region_name=region)

        with open(file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                else:
                    s3_get_bucket_policy(line)
    except FileNotFoundError as e:
        print("{} not found".format(file))
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidClientTokenId':
            sys.exit("The AWS KEY IS INVALID. Exiting")
        elif e.response['Error']['Code'] == 'NotSignedUp':
            print('{} : doesnt have s3 access' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print("Unexpected error: {}" .format(e))
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")


def s3_download_file(bucket, file):
    '''
    download a file from a S3 bucket
    '''
    try:
        client = boto3.resource('s3', region_name=region)
        full_path = os.getcwd()+'/loot/'+bucket+'/'+file
        a = os.path.split(os.path.abspath(full_path))
        if not os.path.exists(a[0]):
            print("[-] Making folder for download [-]")
            os.makedirs(a[0])
            client.Bucket(bucket).download_file(file, full_path)
            print("[+] File downloaded to: {} ]+]".format(full_path))
        else:
            print("[-] Download folder exists... [-]")
            client.Bucket(bucket).download_file(file, full_path)
            print("[+] File downloaded to: {} ]+]".format(full_path))

    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == "404":
            print("{} object does not exist.".format(file))
        elif e.response['Error']['Code'] == 'InvalidClientTokenId':
            sys.exit("The AWS KEY IS INVALID. Exiting")
        elif e.response['Error']['Code'] == 'NotSignedUp':
            print('{} : doesnt have s3 access' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print("Unexpected error: {}" .format(e))
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")


def s3_upload_file(bucket, source_file, dest_file):
    '''
    upload a file to a S3 bucket
    '''
    try:
        client = boto3.resource('s3', region_name=region)
        client.meta.client.upload_file(source_file, bucket, dest_file)

        print("{} uploaded to: {}/{}".format(source_file, bucket, dest_file))
    except FileNotFoundError as e:
        print("[-] {} not found [-]".format(source_file))
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == "404":
            print("{} object does not exist.".format(source_file))
        elif e.response['Error']['Code'] == 'InvalidClientTokenId':
            sys.exit("The AWS KEY IS INVALID. Exiting")
        elif e.response['Error']['Code'] == 'NotSignedUp':
            print('{} : doesnt have s3 access' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print("Unexpected error: {}" .format(e))
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")

def s3_get_file_acl(bucket, file):
    '''
    get file in a s3 bucket ACL
    '''
    try:
        client = boto3.client('s3', region_name=region)
        object_acl = client.get_object_acl(Bucket=bucket, Key=file)
        if object_acl:
            print("{} ACL:\n".format(file))
            print("{}".format(object_acl['Grants']))
    except FileNotFoundError as e:
        print("[-] {} not found [-]".format(file))
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == "404":
            print("{} object does not exist.".format(file))
        elif e.response['Error']['Code'] == 'InvalidClientTokenId':
            sys.exit("The AWS KEY IS INVALID. Exiting")
        elif e.response['Error']['Code'] == 'NotSignedUp':
            print('{} : doesnt have s3 access' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print("Unexpected error: {}" .format(e))
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")
