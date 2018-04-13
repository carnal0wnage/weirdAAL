'''
queries that interact with db can go here
'''


import sqlite3
from sqlite3 import Error

from  libs.sql import *

from config import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY

#  for a key, what services does it have listed in the DB
def step_show_services_by_key():
    db_name = "weirdAAL.db"
    results = search_recon_by_key(db_name,AWS_ACCESS_KEY_ID)
    print("Services enumerated for {}".format(AWS_ACCESS_KEY_ID))
    for result in results:
    	print("{}:{}".format(result[0],result[1]))

#same as show_sevices
def step_list_services_by_key():
    db_name = "weirdAAL.db"
    results = search_recon_by_key(db_name,AWS_ACCESS_KEY_ID)
    print("Services enumerated for {}".format(AWS_ACCESS_KEY_ID))
    for result in results:
    	print("{}:{}".format(result[0],result[1]))