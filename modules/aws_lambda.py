'''
This file is used to list lambda functions and event mappings
'''
from libs.aws_lambda import *


def module_lambda_list_functions():
    list_functions()


def module_lambda_list_event_source_mappings():
    list_event_source_mappings()


def module_lambda_get_function(*text):
	'''
	get specfied function. Takes function name from list_functions and region the function exists in

	'''
	lambda_get_function(text[0][0], text[0][1])