'''
Module for interacting with the config service
'''

from libs.config import *

def module_config_list_all_rules():
    list_all_config_rules()

def module_config_list_all_recorders():
    list_all_config_recorders()

def module_config_delete_rule(*args):
    try:
        if args[0][0] and args[0][1]:
            delete_config_rule(args[0][0], args[0][1])
    except IndexError:
        print("You must provide the rule name and region name: -a someRuleName,us-east-1")

def module_config_delete_recorder(*args):
    try:
        if args[0][0] and args[0][1]:
            delete_config_recorder(args[0][0], args[0][1])
    except IndexError:
        print("You must provide the recorder name and region name: -a someRecorderName,us-east-1")
