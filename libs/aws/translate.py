'''
Translate functions for WeirdAAL
'''

import boto3
import botocore
import pprint
import sys


pp = pprint.PrettyPrinter(indent=5, width=80)

# from http://docs.aws.amazon.com/general/latest/gr/rande.html
regions = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'af-south-1', 'ap-east-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3', 'ap-south-1', 'ap-southeast-1', 'ap-southeast-2', 'ca-central-1', 'cn-north-1', 'cn-northwest-1', 'eu-central-1', 'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-south-1', 'eu-north-1', 'me-south-1', 'sa-east-1', 'us-gov-west-1', 'us-gov-east-1']

'''
Code to get the AWS_ACCESS_KEY_ID from boto3
'''
session = boto3.Session()
credentials = session.get_credentials()
AWS_ACCESS_KEY_ID = credentials.access_key


def translate_text(text, source_lang, target_lang):
    '''
    Translate a block of text from source to target language
    Available languages: English (en), Arabic (ar), Chinese (Simplified) (zh), French (fr), German (de), Portuguese (pt), Spanish (es)
    http://boto3.readthedocs.io/en/latest/reference/services/translate.html
    '''
    try:
        for region in regions:
            client = boto3.client('translate', region_name=region)
            response = client.translate_text(Text=text, SourceLanguageCode=source_lang, TargetLanguageCode=target_lang)
            # print(response)
            if response.get('TranslatedText') is None:
                print("{} likely does not have Translate permissions\n" .format(AWS_ACCESS_KEY_ID))
            elif len(response['TranslatedText']) <= 0:
                print("[-] TranslateText allowed for {} but no results [-]" .format(region))
            else:
                print("### {}: Translated Text  ###\n" .format(region))
                print("Translated Text: {}".format(response['TranslatedText']))
                print("\n")
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'UnauthorizedOperation':
            print('{} : (UnauthorizedOperation) when calling the Pricing DescribeServices' .format(AWS_ACCESS_KEY_ID))
        elif e.response['Error']['Code'] == 'SubscriptionRequiredException':
            print('{} : Has permissions but isnt signed up for service - usually means you have a root account' .format(AWS_ACCESS_KEY_ID))
        else:
            print(e)
    except KeyboardInterrupt:
        print("CTRL-C received, exiting...")
