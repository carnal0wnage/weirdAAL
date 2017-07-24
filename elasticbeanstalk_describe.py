'''
This file is used to perform some ElasticBeanstalk actions
'''
from libs.elasticbeanstalk import *
from config import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY

#describe_applications(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
#describe_application_versions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
#describe_configuration_options(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
describe_environments(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
describe_events(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
