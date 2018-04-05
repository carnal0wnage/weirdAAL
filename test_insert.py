import sqlite3
from sqlite3 import Error

from  libs.sql import *


#create some tables to stick data in

if __name__ == "__main__":
    db_name = "weirdAAL.db"

    test_aws_key = [("AKIAIOSFODNN7EXAMPLE", "some test shit")]
    insert_awskey_data(db_name,test_aws_key)

    test_service_data = [("AKIAIOSFODNN7EXAMPLE","ec2","DescribeInstances"),("AKIAIOSFODNN7EXAMPLE","ecr","DescribeRepositories")]
    insert_reconservice_data(db_name, test_service_data)