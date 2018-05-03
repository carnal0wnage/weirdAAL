'''
S3 functions for WeirdAAL
'''

import boto3
import botocore
import pprint

pp = pprint.PrettyPrinter(indent=5, width=80)

'''
Code to get the AWS_ACCESS_KEY_ID from boto3
'''
session = boto3.Session()
credentials = session.get_credentials()
AWS_ACCESS_KEY_ID = credentials.access_key
AWS_SECRET_ACCESS_KEY = credentials.secret_key


def get_s3bucket_policy(bucket):
    client = boto3.client(
            's3',
            region_name='us-east-1'
    )
    
    try:
        bucket = bucket
        print('\n#### Trying to enumate s3 buckets and bucket policy & ACL for {} ####' .format(bucket))

        try:
            for key in client.list_objects(Bucket=bucket,MaxKeys=100)['Contents']:
                print('[+] '+ key['Key'].encode('utf-8').strip())
                #print(key['Key']) #first 100 results
        except KeyError as e:
            print ("KeyError havent tracked down reason yet")
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                print('{} : cant list s3 bucket [AccessDenied]' .format(AWS_ACCESS_KEY_ID))
            elif e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                print('%s: Has No S3 Policy!' % bucket['Name'])
            elif e.response['Error']['Code'] == 'AllAccessDisabled':
                print('{} : cant list s3 bucket [AllAccessDisabled]' .format(AWS_ACCESS_KEY_ID))
            else:
                print ("Unexpected error: {}" .format(e))
        except KeyboardInterrupt:
            print("CTRL-C received, exiting...")
            
        try:
            policy = client.get_bucket_policy(Bucket=bucket)
            if policy:
                print(bucket + " Policy: ")
                pp.pprint(policy['Policy'])
                print("\n")
            else:
                pass
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                print('{} : cant list s3 bucket policy [AccessDenied]' .format(AWS_ACCESS_KEY_ID))
            elif e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                print('{}: Has No S3 Policy!' .format(bucket))
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
                print(bucket + " Grants: ")
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

#specifically get the acl on a file in a buckeet
def get_s3object_acl(bucket, myfile):
    client = boto3.client(
            's3',
            region_name='us-east-1'
    )
    
    try:
        bucket = bucket
        myobject = myfile
        print('#### Trying to enumate s3 ACL for {}:{} ####\n '.format(bucket, myfile))
        acl = client.get_object_acl(Bucket=bucket,Key=myfile)
        print (acl)
        
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

#given an aws keypair what s3 assets does it have permission to
def get_s3objects_for_account():
    client = boto3.resource(
            's3',
            region_name='us-east-1'
    )
    
    try:
        print('#### Trying to list s3 bucketsfor {} ####\n '.format(AWS_ACCESS_KEY_ID))
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


def get_s3objects_for_account_detailed():
    client = boto3.resource(
            's3',
            region_name='us-east-1'
    )
    
    try:
        print('#### Trying to list s3 bucketsfor {} ####\n '.format(AWS_ACCESS_KEY_ID))
        for bucket in client.buckets.all():
            print(bucket.name)
            get_s3bucket_policy(bucket.name)
        
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
