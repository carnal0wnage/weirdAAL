'''
Module for interacting with the config service
'''

from libs.aws.config import *


def module_config_list_all_rules():
    '''
    Config list all rules
    python3 weirdAAL.py -m config_list_all_rules -t demo
    '''
    list_all_config_rules()


def module_config_list_all_recorders():
    '''
    Config list all recorders
    python3 weirdAAL.py -m config_list_all_recorders -t demo
    '''
    list_all_config_recorders()


def module_config_delete_rule(*args):
    '''
    Config delete the specified rule
    python3 weirdAAL.py -m config_delete_rule -a someRuleName,us-east-1 -t demo
    '''
    try:
        if args[0][0] and args[0][1]:
            delete_config_rule(args[0][0], args[0][1])
    except IndexError:
        print("You must provide the rule name and region name: -a someRuleName,us-east-1")


def module_config_delete_recorder(*args):
    '''
    Config delete the specified recorder
    python3 weirdAAL.py -m config_delete_recorder -a someRecorderName,us-east-1 -t demo
    '''
    try:
        if args[0][0] and args[0][1]:
            delete_config_recorder(args[0][0], args[0][1])
    except IndexError:
        print("You must provide the recorder name and region name: -a someRecorderName,us-east-1")
