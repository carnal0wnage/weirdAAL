'''
Custom SQL/database functions for WeirdAAL
'''

import sqlite3
from sqlite3 import Error


def create_table(db_name, table_name, sql):
    '''
    SQLite3 create table function
    '''
    with sqlite3.connect(db_name) as db:
        cursor = db.cursor()
        cursor.execute("""SELECT name FROM sqlite_master WHERE name=?""", (table_name,))
        result = cursor.fetchall()
        keep_table = True
        if len(result) == 1:
            response = input("The table {} already exists, do you wish to recreate it? (y/n): ".format(table_name))
            if response == "y":
                keep_table = False
                print("The {} table will be recreated - all existing data will be lost".format(table_name))
                cursor.execute("drop table if exists {}".format(table_name))
                db.commit()
            else:
                print("The existing table was kept")
        else:
            keep_table = False
        if not keep_table:
            cursor.execute(sql)
            db.commit()


def create_recon_table(db_name, table_name):
    '''
    Create recon table service:subservice:AWSKeyID,time
    '''
    sql = """CREATE TABLE recon
             (ID integer,
             service text,
             sub_service text,
             AWSKeyID text,
             target text,
             checked_at timestamp,
             PRIMARY KEY (ID))"""
             # FOREIGN KEY (AWSKeyID) references AWSKey(ID))"""
    create_table(db_name, table_name, sql)
    print("created table: {}".format(table_name))


def create_awskey_table(db_name, table_name):
    '''
    Create awskey table (currently unused)
    '''
    sql = """CREATE TABLE AWSKey
             (ID integer,
             AWSKeyID text,
             description text,
             target text,
             PRIMARY KEY(ID))"""
    create_table(db_name, table_name, sql)
    print("created table: {}".format(table_name))


def create_services_table(db_name, table_name):
    '''
    Create services table - service:sub_service:sub_service_data
    '''
    sql = """CREATE TABLE services
             (ID integer,
             AWSKeyID Text,
             service text,
             sub_service text,
             sub_service_data text,
             checked_at timestamp,
             target text,
             PRIMARY KEY(ID))"""
    create_table(db_name, table_name, sql)
    print("created table: {}".format(table_name))


def insert_awskey_data(db_name, records):
    '''
    Insert AWS Key and a description to the AWSKey table (unused)
    '''
    sql = """INSERT INTO AWSKey(AWSKeyID, description, target) VALUES (?,?,?)"""
    for record in records:
        query(db_name, sql, record)


def insert_reconservice_data(db_name, records):
    '''
    Insert data into the recon table
    '''
    sql = """INSERT INTO recon(service, sub_service, AWSKeyID, target, checked_at) VALUES (?,?,?,?,?)"""
    for record in records:
        query(db_name, sql, record)


def insert_sub_service_data(db_name, records):
    '''
    Insert service, sub_service & sub_service data into the DB
    '''
    sql = """INSERT INTO services(service, sub_service, sub_service_data, AWSKeyID, target, checked_at) VALUES (?,?,?,?,?,?)"""
    for record in records:
        query(db_name, sql, record)


def search_recon_by_key(db_name, AWSKeyID):
    '''
    Function to query services by AWSKey and order them by time
    '''
    with sqlite3.connect(db_name) as db:
        cursor = db.cursor()
        cursor.execute("""SELECT DISTINCT service, sub_service, checked_at FROM recon WHERE AWSKeyID=? ORDER BY datetime(checked_at)""", (AWSKeyID,))
        results = cursor.fetchall()
        return results

def search_recon_for_targets(db_name, AWSKeyID):
    '''
    Function to query services by AWSKey and order them by time
    '''
    with sqlite3.connect(db_name) as db:
        cursor = db.cursor()
        cursor.execute("""SELECT DISTINCT target from recon""")
        results = cursor.fetchall()
        return results

def search_list_awskeys_in_database(db_name, AWSKeyID):
    '''
    Function to query for all AWSKeys in the database
    '''
    with sqlite3.connect(db_name) as db:
        cursor = db.cursor()
        cursor.execute("""SELECT DISTINCT AWSKeyID,target from recon""")
        results = cursor.fetchall()
        return results


def search_list_awskeys_by_target(db_name, target):
    '''
    Function to query for all AWSKeys in the database
    '''
    with sqlite3.connect(db_name) as db:
        cursor = db.cursor()
        cursor.execute("""SELECT DISTINCT AWSKeyID from recon WHERE target=?""", (target,))
        results = cursor.fetchall()
        return results


def query(db_name, sql, data):
    '''
    Generic query function
    '''
    with sqlite3.connect(db_name) as db:
        cursor = db.cursor()
        # cursor.execute("""PRAGMA foreign_keys = ON""")
        cursor.execute(sql, data)
        db.commit()
