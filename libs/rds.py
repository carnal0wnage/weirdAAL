import boto3
import botocore
import pprint

pp = pprint.PrettyPrinter(indent=5, width=80)

#from http://docs.aws.amazon.com/general/latest/gr/rande.html
regions = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ca-central-1', 'eu-central-1', 'eu-west-1', 'eu-west-2', 'ap-northeast-1', 'ap-northeast-2', 'ap-southeast-1', 'ap-southeast-2',  ]


def describe_db_instances(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
    print("doing stuff")
    try:
        for region in regions:
            client = boto3.client(
                'rds',
                aws_access_key_id = AWS_ACCESS_KEY_ID,
                aws_secret_access_key = AWS_SECRET_ACCESS_KEY,
                region_name=region
            )

            instances = client.describe_db_instances()
            for r in instances['DBInstances']:
                for i in r['Instances']:
                    pp.pprint(i)

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
