'''
Queries that interact with the db
'''

import boto3
import sqlite3
from sqlite3 import Error

from libs.sql import *

session = boto3.Session()
credentials = session.get_credentials()
AWS_ACCESS_KEY_ID = credentials.access_key

db_name = "weirdAAL.db"

#  for a key, what services does it have listed in the DB


def step_show_services_by_key():
    '''
    Show services for a given key service:sub_service
    example: elasticbeanstalk:DescribeEvents
    '''
    results = search_recon_by_key(db_name, AWS_ACCESS_KEY_ID)
    print("Services enumerated for {}".format(AWS_ACCESS_KEY_ID))
    for result in results:
        print("{}:{}".format(result[0], result[1]))


def step_show_services_by_key_with_date():
    '''
    Show services for a given key service:sub_service
    example: elasticbeanstalk:DescribeEvents
    '''
    results = search_recon_by_key(db_name, AWS_ACCESS_KEY_ID)
    print("Services enumerated for {}".format(AWS_ACCESS_KEY_ID))
    for result in results:
        print("{}:{} -> Date: {}".format(result[0], result[1], result[2]))

# same as show_sevices


def step_list_services_by_key():
    '''
    Show services for a given key service:sub_service
    example: elasticbeanstalk:DescribeEvents
    '''
    results = search_recon_by_key(db_name, AWS_ACCESS_KEY_ID)
    print("Services enumerated for {}".format(AWS_ACCESS_KEY_ID))
    for result in results:
        print("{}:{}".format(result[0], result[1]))


# for a key, what services does it have listed in the DB and the date


def step_list_services_by_key_with_date():
    '''
    Show services for a given key service:sub_service with date
    example: elasticbeanstalk:DescribeEvents -> Date: 2018-04-18 20:36:41.791780
    '''
    results = search_recon_by_key(db_name, AWS_ACCESS_KEY_ID)
    print("Services enumerated for {}".format(AWS_ACCESS_KEY_ID))
    for result in results:
        print("{}:{} -> Date: {}".format(result[0], result[1], result[2]))
