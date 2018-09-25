'''
This file is used to perform some ElasticBeanstalk actions
'''
from libs.aws.elasticbeanstalk import *


'''
There is a weird issue that AWS says everyone has elasticbeanstalk permissions
despite not running any of these services - in other words it won't be abnormal
for recon to say it has elasticbeantalk permissions but nothing gets returned
when you run these functions
'''


def module_elasticbeanstalk_describe_applications():
    '''
    Elasticbeanstalk Describe Applications
    python3 weirdAAL.py -m elasticbeanstalk_describe_applications -t demo
    '''
    elasticbeanstalk_describe_applications()


def module_elasticbeanstalk_describe_applications_versions():
    '''
    Elasticbeanstalk Describe Application versions
    python3 weirdAAL.py -m elasticbeanstalk_describe_applications_versions -t demo
    '''
    elasticbeanstalk_describe_application_versions()

# not working
# def module_elasticbeanstalk_describe_configuration_options():
#   elasticbeanstalk_describe_configuration_options()


def module_elasticbeanstalk_describe_environments():
    '''
    Elasticbeanstalk Describe Environments
    python3 weirdAAL.py -m elasticbeanstalk_describe_environments -t demo
    '''
    elasticbeanstalk_describe_environments()


def module_elasticbeanstalk_describe_events():
    '''
    Elasticbeanstalk describe events
    python3 weirdAAL.py -m elasticbeanstalk_describe_events -t demo
    '''
    elasticbeanstalk_describe_events()


def module_elasticbeanstalk_check_defaults():
    '''
    Test for all 4 of the deault elasticbeanstalk permissions
    python3 weirdAAL.py -m elasticbeanstalk_check_defaults -t demo
    '''
    elasticbeanstalk_describe_applications()
    elasticbeanstalk_describe_application_versions()
    elasticbeanstalk_describe_environments()
    elasticbeanstalk_describe_events()
