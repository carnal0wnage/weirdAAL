import boto3
import botocore
import pprint

pp = pprint.PrettyPrinter(indent=5, width=80)

# from https://docs.aws.amazon.com/general/latest/gr/rande.html#sqs_region
regions = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3', 'ap-south-1', 'ap-southeast-1', 'ap-southeast-2', 'ca-central-1', 'cn-north-1', 'cn-northwest-1', 'eu-central-1', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'sa-east-1', 'us-gov-west-1'  ]


def sqs_list_queues(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
    try:
        for region in regions:
            client = boto3.client("sqs", aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
            response = client.list_queues()
            # THis isnt working need to test with one that works to get the QueueUrl attributes
            # if len(response['QueueUrls']) <= 0:
            #    print("[-] ListQueues allowed for {} but no results [-]" .format(region))
            # else:
            print("region: {} \n {}".format(region,response))

    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'InvalidClientTokenId':
            sys.exit("{} : The AWS KEY IS INVALID. Exiting" .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'AccessDenied':
            print('{} : Does not have the required permissions' .format(AWS_ACCESS_KEY_ID))
        else:
            print("Unexpected error: {}" .format(e))
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")

