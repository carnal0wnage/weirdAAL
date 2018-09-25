'''
Create the sqlite3 database for WeirdAAL
'''

import builtins
import sqlite3
from sqlite3 import Error

from libs.aws.sql import *



# Provides us with a global var "db_name" we can access anywhere
builtins.db_name = "weirdAAL.db"

# create some tables to stick data in

if __name__ == "__main__":
    create_awskey_table(db_name, "AWSKey")
    create_recon_table(db_name, "recon")
    create_services_table(db_name,"services")
