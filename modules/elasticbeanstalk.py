'''
This file is used to perform some ElasticBeanstalk actions
'''
from libs.elasticbeanstalk import *


'''
There is a weird issue that AWS says everyone has elasticbeanstalk permissions
despite not running any of these services - in other words it wont be abnormal
for recon to say it has elasticbeantalk permissions but nothing get returned
when you run these functions
'''


def step_elasticbeanstalk_describe_applications():
    describe_applications()


def step_elasticbeanstalk_describe_applications_versions():
    describe_application_versions()

# not working
# def step_elasticbeanstalk_describe_configuration_options():
#   describe_configuration_options()


def step_elasticbeanstalk_describe_environments():
    describe_environments()


def step_elasticbeanstalk_describe_events():
    describe_events()
