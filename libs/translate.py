import boto3
import botocore
import pprint
import sys

'''
Translate functions for WeirdAAL
'''

pp = pprint.PrettyPrinter(indent=5, width=80)

#from http://docs.aws.amazon.com/general/latest/gr/rande.html
regions = ['us-east-1', 'us-east-2', 'us-west-2', 'eu-west-1' ]

'''
Code to get the AWS_ACCESS_KEY_ID from boto3
'''
session = boto3.Session()
credentials = session.get_credentials()
AWS_ACCESS_KEY_ID = credentials.access_key

def translate_text(text, source_lang, target_lang):
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