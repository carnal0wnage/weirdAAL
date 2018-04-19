import sqlite3
from sqlite3 import Error

from  libs.sql import *


#create some tables to stick data in

if __name__ == "__main__":
    db_name = "weirdAAL.db"
    create_awskey_table(db_name, "AWSKey")
    create_recon_table(db_name, "recon")
    create_services_table(db_name,"services")