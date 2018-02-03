# Weird AAL
Weird AWS Attack Library (AAL)

<img src="http://earnthis.net/wp-content/uploads/2013/12/150490_large.jpg"  align="center" height="240" width="350">

# Description

Did you stumble across AWS keys somehow? Great, because this tool was built to help you take advantage of those keys.

# Installation

## Python3 and libraries for weirdAAL

You need Python3 / Pip3 installed on your system.

```
pip3 install -r requirements.txt
```

## Environment

The tool needs keys. To make this easy, copy `env.sample` to `.env` in this directory.



# Usage

```
./weirdAAL -h
```

---

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
