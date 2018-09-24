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


# for a key, what services does it have listed in the DB


def module_show_services_by_key():
    '''
    Show services for a given key service:sub_service
    example: elasticbeanstalk:DescribeEvents
    '''
    results = ["{}.{}".format(r[0], r[1]) for r in search_recon_by_key(db_name, AWS_ACCESS_KEY_ID)]
    print("Services enumerated for {}".format(AWS_ACCESS_KEY_ID))
    for result in sorted(results):
        print(result)


def module_show_services_by_key_with_date():
    '''
    Show services for a given key service:sub_service
    example: elasticbeanstalk:DescribeEvents -> Date: 2018-04-18 20:36:41.791780
    '''
    results = [("{}.{}".format(r[0], r[1]), r[2]) for r in search_recon_by_key(db_name, AWS_ACCESS_KEY_ID)]
    print("Services enumerated for {}".format(AWS_ACCESS_KEY_ID))
    for result, date in sorted(results, key=lambda r: r[0]):
        print("{} -> Date: {}".format(result, date))

# same as show_sevices


def module_list_services_by_key():
    '''
    Show services for a given key service:sub_service
    example: elasticbeanstalk:DescribeEvents
    '''
    results = ["{}.{}".format(r[0], r[1]) for r in search_recon_by_key(db_name, AWS_ACCESS_KEY_ID)]
    print("Services enumerated for {}".format(AWS_ACCESS_KEY_ID))
    for result in sorted(results):
        print(result)


# for a key, what services does it have listed in the DB and the date


def module_list_services_by_key_with_date():
    '''
    Show services for a given key service:sub_service with date
    example: elasticbeanstalk:DescribeEvents -> Date: 2018-04-18 20:36:41.791780
    '''
    results = [("{}.{}".format(r[0], r[1]), r[2]) for r in search_recon_by_key(db_name, AWS_ACCESS_KEY_ID)]
    print("Services enumerated for {}".format(AWS_ACCESS_KEY_ID))
    for result, date in sorted(results, key=lambda r: r[0]):
        print("{} -> Date: {}".format(result, date))
