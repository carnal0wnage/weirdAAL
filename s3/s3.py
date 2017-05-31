#s3 functions go here

import boto3
import botocore
import pprint

pp = pprint.PrettyPrinter(indent=5, width=80)

def get_s3bucket_policy(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, bucket):
    client = boto3.client(
            's3',
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
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
            print "KeyError havent tracked down reason yet"
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                print('%s : cant list s3 bucket [AccessDenied]' % AWS_ACCESS_KEY_ID)
            elif e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                print('%s: Has No S3 Policy!' % bucket['Name'])
            elif e.response['Error']['Code'] == 'AllAccessDisabled':
                print('%s : cant list s3 bucket [AllAccessDisabled]' % AWS_ACCESS_KEY_ID)
            else:
                print "Unexpected error: %s" % e
            
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
                print('%s : cant list s3 bucket policy [AccessDenied]' % AWS_ACCESS_KEY_ID)
            elif e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                print('%s: Has No S3 Policy!' % bucket)
                print("\n")
            elif e.response['Error']['Code'] == 'AllAccessDisabled':
                print('%s : cant list s3 bucket policy [AllAccessDisabled]' % AWS_ACCESS_KEY_ID)
            else:
                print "Unexpected error: %s" % e
                    
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
                print('%s : cant list s3 bucket acl [AccessDenied]' % AWS_ACCESS_KEY_ID)
            elif e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                print('%s: Has No S3 Policy!' % bucket)
                print("\n")
            elif e.response['Error']['Code'] == 'AllAccessDisabled':
                print('%s : cant list s3 bucket acl [AllAccessDisabled]' % AWS_ACCESS_KEY_ID)
            else:
                print "Unexpected error: %s" % e

    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidClientTokenId':
            sys.exit("The AWS KEY IS INVALID. Exiting")
        elif e.response['Error']['Code'] == 'NotSignedUp':
            print('%s : doesnt have s3 access' % AWS_ACCESS_KEY_ID)
        else:
            print "Unexpected error: %s" % e

def get_s3object_acl(access_key, secret_key, bucket, myfile):
    client = boto3.client(
            's3',
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
            region_name='us-east-1'
    )
    
    try:
        bucket = bucket
        myobject = myfile
        print('#### Trying to enumate s3 ACL for %s:%s ####\n ' % (bucket, myfile))
        acl = client.get_object_acl(Bucket=bucket,Key=myfile)
        print acl
        
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidClientTokenId':
            sys.exit("The AWS KEY IS INVALID. Exiting")
        elif e.response['Error']['Code'] == 'NotSignedUp':
            print('%s : doesnt have s3 access' % AWS_ACCESS_KEY_ID)
        else:
            print "Unexpected error: %s" % e
