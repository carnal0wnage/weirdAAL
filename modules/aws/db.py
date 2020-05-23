'''
Queries that interact with the db
'''

import boto3
import sqlite3
from sqlite3 import Error

from libs.aws.sql import *

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
    print("[+] Services enumerated for {} [+]".format(AWS_ACCESS_KEY_ID))
    for result in sorted(results):
        print(result)


def module_show_services_by_key_with_date():
    '''
    Show services for a given key service:sub_service
    example: elasticbeanstalk:DescribeEvents -> Date: 2018-04-18 20:36:41.791780
    '''
    results = [("{}.{}".format(r[0], r[1]), r[2]) for r in search_recon_by_key(db_name, AWS_ACCESS_KEY_ID)]
    print("[+] Services enumerated for {} [+]".format(AWS_ACCESS_KEY_ID))
    for result, date in sorted(results, key=lambda r: r[0]):
        print("{} -> Date: {}".format(result, date))

# same as show_sevices


def module_list_services_by_key():
    '''
    Show services for a given key service:sub_service
    example: elasticbeanstalk:DescribeEvents
    '''
    results = ["{}.{}".format(r[0], r[1]) for r in search_recon_by_key(db_name, AWS_ACCESS_KEY_ID)]
    print("[+] Services enumerated for {} [+]".format(AWS_ACCESS_KEY_ID))
    for result in sorted(results):
        print(result)


# for a key, what services does it have listed in the DB and the date


def module_list_services_by_key_with_date():
    '''
    Show services for a given key service:sub_service with date
    example: elasticbeanstalk:DescribeEvents -> Date: 2018-04-18 20:36:41.791780
    '''
    results = [("{}.{}".format(r[0], r[1]), r[2]) for r in search_recon_by_key(db_name, AWS_ACCESS_KEY_ID)]
    print("[+] Services enumerated for {} [+]".format(AWS_ACCESS_KEY_ID))
    for result, date in sorted(results, key=lambda r: r[0]):
        print("{} -> Date: {}".format(result, date))


# for a database, show all the targets in the DB


def module_list_targets_in_database():
    '''
    Show targets in the database
    python3 weirdAAL.py -m list_targets_in_databse -t demo
    '''
    results = ["{}".format(r[0]) for r in search_recon_for_targets(db_name, AWS_ACCESS_KEY_ID)]
    print("[+] Targets in the database [+]")
    for result in sorted(results):
        print(result)


# for a key, what services does it have listed in the DB and the date


def module_list_services_by_provided_key_with_date(*text):
    '''
    Show services for a given key service:sub_service with date
    weirdAAL.py -m list_services_by_provided_key_with_date -a 'AKIAEXAMPLE' -t demo
    '''
    AWS_ACCESS_KEY_ID = text[0][0]
    results = [("{}.{}".format(r[0], r[1]), r[2]) for r in search_recon_by_key(db_name, AWS_ACCESS_KEY_ID)]
    print("[+] Services enumerated for {} [+]".format(AWS_ACCESS_KEY_ID))
    for result, date in sorted(results, key=lambda r: r[0]):
        print("{} -> Date: {}".format(result, date))


# for a key, what services does it have listed in the DB


def module_list_services_by_provided_key(*text):
    '''
    Show services for a given key service:sub_service with date
    weirdAAL.py -m list_services_by_provided_key -a 'AKIAEXAMPLE' -t demo
    '''
    AWS_ACCESS_KEY_ID = text[0][0]
    results = ["{}.{}".format(r[0], r[1]) for r in search_recon_by_key(db_name, AWS_ACCESS_KEY_ID)]
    print("[+] Services enumerated for {} [+]".format(AWS_ACCESS_KEY_ID))
    for result in sorted(results):
        print(result)


# Show all AWS Keys in the DB


def module_list_awskeys_in_database():
    '''
    Show all AWS Keys in the database
    weirdAAL.py -m list_awskeys_in_database -t demo
    '''
    results = [("{}.{}".format(r[0], r[1])) for r in search_list_awskeys_in_database(db_name, AWS_ACCESS_KEY_ID)]
    print("[+] Listing of AWS Keys in the database [+]")
    for result in sorted(results):
        print(result)


# List AWS Keys for as specified target


def module_list_awskeys_for_target(*text):
    '''
    Show all AWS Keys in the database
    weirdAAL.py -m list_awskeys_for_target -a 'othertarget' -t demo
    '''
    target = text[0][0]
    results = [("{}".format(r[0])) for r in search_list_awskeys_by_target(db_name, target)]
    print("[+] Listing of AWS Keys for target:{} [+]".format(target))
    for result in sorted(results):
        print(result)