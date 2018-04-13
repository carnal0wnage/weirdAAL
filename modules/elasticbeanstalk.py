'''
This file is used to perform some ElasticBeanstalk actions
'''
from libs.elasticbeanstalk import *
from config import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY


'''
There is a weird issue that AWS says everyone has elasticbeanstalk permissions
despite not running any of these services - in other words it wont be abnormal
for recon to say it has elasticbeantalk permissions but nothing get returned
when you run these functions
'''


def step_elasticbeanstalk_describe_applications():
    describe_applications(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)


def step_elasticbeanstalk_describe_applications_versions():
    describe_application_versions(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)

# not working
# def step_elasticbeanstalk_describe_configuration_options():
#   describe_configuration_options(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)


def step_elasticbeanstalk_describe_environments():
    describe_environments(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)


def step_elasticbeanstalk_describe_events():
    describe_events(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
