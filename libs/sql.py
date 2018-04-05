import sqlite3
from sqlite3 import Error

def create_table(db_name,table_name,sql):
    with sqlite3.connect(db_name) as db:
        cursor = db.cursor()
        cursor.execute("""SELECT name FROM sqlite_master WHERE name=?""",(table_name,))
        result = cursor.fetchall()
        keep_table = True
        if len(result) == 1:
            #python 2
            response = raw_input("The table {} already exists, do you wish to recreate it? (y/n): ".format(table_name))
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
    sql = """CREATE TABLE recon
             (ID integer,
             service text,
             sub_service text,
             AWSKeyID text,
             checked_at text,
             PRIMARY KEY (ID))"""
             #FOREIGN KEY (AWSKeyID) references AWSKey(ID))"""
    create_table(db_name,table_name,sql)
    print ("created table: {}".format(table_name))

def create_awskey_table(db_name, table_name):
    sql = """CREATE TABLE AWSKey
             (ID integer,
             AWSKeyID Text,
             Description text,
             PRIMARY KEY(ID))"""
    create_table(db_name,table_name,sql)
    print ("created table: {}".format(table_name))


def insert_awskey_data(db_name, records):
    sql = """INSERT INTO AWSKey(AWSKeyID, Description) VALUES (?,?)"""
    for record in records:
        query(db_name, sql,record)

def insert_reconservice_data(db_name, records):
    sql = """INSERT INTO recon(service, sub_service, AWSKeyID, checked_at) VALUES (?,?,?,?)"""
    for record in records:
        query(db_name,sql,record)

def search_recon_by_key(db_name,AWSKeyID):
        with sqlite3.connect(db_name) as db:
                cursor = db.cursor()
                cursor.execute("""SELECT service,sub_service FROM recon WHERE AWSKeyID=?""",(AWSKeyID,))
                results = cursor.fetchall()
                return results

def query(db_name,sql,data):
    with sqlite3.connect(db_name) as db:
        cursor = db.cursor()
        #cursor.execute("""PRAGMA foreign_keys = ON""")
        cursor.execute(sql,data)
        db.commit()
        
