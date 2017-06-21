# Weird AAL
Weird AWS Attack Library (AAL) 

<img src="http://earnthis.net/wp-content/uploads/2013/12/150490_large.jpg"  align="center" height="240" width="350">

# Examples

## IAM
- iam_pwn.py  -- given a ROOT or account with IAM access manipulate user access keys, MFA, console passwords or create a backdoor user

## S3 Examples

- s3_list_bucket_contents.py  -- list the contents of a single bucket
- s3_list_bucket_contents_fromfile.py  --list the contents of a bucket from a list of buckets
- s3_list_buckets_for_acct.py -- show s3 buckets available to a particular key
- s3_list_buckets_and_contents.py -- list buckets AND contents (first 100) for a key

## EC2
- ec2_review_encrypted_volumes.py -- review ec2 instances for encryption status -write out unencrypted ones to file
     (port of https://gist.github.com/cktricky/0fa3b13ca4306bcd1ec384e88eac3f55)




