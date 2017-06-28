'''
list config and other logging info
port of https://gist.github.com/cktricky/f19e8d55ea5dcb1fdade6ede588c6576
'''

from libs.config import *

#from http://docs.aws.amazon.com/general/latest/gr/rande.html
regions = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'ca-central-1', 'eu-central-1', 'eu-west-1', 'eu-west-2', 'ap-northeast-1', 'ap-northeast-2', 'ap-southeast-1', 'ap-southeast-2',  ]

def print_section_header_and_footer(text, end=False):
	print("-" * 50)
	print(text)
	print("-" * 50)

	if end:
		print("\n\n")

def print_config_text(text):
	print("#" * len(text))


print_section_header_and_footer("BEGINNING OF CONFIG SERVICE REVIEW")

for region in regions:
	response = describe_configuration_recorders(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, region)

	config_service_text = "Config Service Recorders"
	print_config_text(config_service_text)
	print(config_service_text)
	print("Region:" + region)
	print_config_text(config_service_text)
	
	if response.get('ConfigurationRecorders') is None:
		print "{} likely does not have Config permissions\n" .format(AWS_ACCESS_KEY_ID)
	elif len(response['ConfigurationRecorders']) <= 0:
		print("NO CONFIGURATION DETECTED")
	else:
		for group in response['ConfigurationRecorders']:
			pp.pprint(group['recordingGroup'])
			pp.pprint(group['recordingGroup']['resourceTypes'])
			#for resourcetype in group['recordingGroup']:
			#	pp.pprint(resourcetype['resourceTypes'][0])

	ruleresponse = describe_configuration_recorders(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, region)
	print ruleresponse
			
print_section_header_and_footer("END OF CONFIG SERVICE REVIEW", True)