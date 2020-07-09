import json
import sys
import urllib.parse
import botocore
import boto3
import io
import gzip
from datetime import datetime



"""
Acknowledgements:
Code and inspiration borrowed heavily from:
https://github.com/matthew-harper/pyCloudTrailProcesser
https://github.com/aws-samples/amazon-rds-data-api-demo/blob/master/src/main/python/lambda_function_postgres.py
"""

"""
ASSUMPTIONS
The database table you are connecting to has the following fields:
Fields:
   - AWSAccountId (VarChar)
   - UserEmail (VarChar)
   - CreationDate (DateTime)
   - AMIId (VarChar)
   - ParentId (VarChar)
   * (note that the parent in ParentId does not  have to be an AMI, it could be an EC2 instance)
"""

s3 = boto3.client('s3')

"""
The variable EVENT_NAMES contains all event name types that you may want to capture.  Our
sample simply captures 'CreateImage' in order to search for valid AMI creation events, but
you can easily modify this to perform other searcheds. 
"""
EVENT_NAMES = {"CreateImage"}

### START AURORA CONNECTION ###
"""
If you want to connect to an Aurora database, uncomment and fill out the variables below
and use the 'write_to_aurora_db' function instead of the 'write_to_mysql_db' in the 
'insert_required_fields' function.  Additionally, comment out the entire section under
between START MYSQL CONNECTION and END MYSQL CONNECTION
"""
# db_name = ''
# cluster_arn = ''
# secret_arn = ''
# db_table = ''
### END AURORA CONNECTION ###

### START MYSQL CONNECTION ###
"""
If you want to connect to a mySQL database, uncomment and fill out the variables below
and use the 'write_to_mysql_db' function in the 'insert_required_fields' function.
Additionally, ensure that all lines between START AURORA CONNECTION and END AURORA
CONNECTION are commented out.
"""
import mysql.connector
from mysql.connector import Error
from mysql.connector import errorcode

db_host = '127.0.0.1'
db_name = 'ami-parentage'
db_table = 'amicreation'
db_user = ''
db_pass = ''
connection = mysql.connector.connect(host=db_host, database=db_name, user=db_user, password=db_pass)
### END MYSQL CONNECTION ###

# FUNCTIONS

def write_to_aurora_db(account_id, user_email, event_time, ami_id, parent_id):
    rds_data = boto3.client('rds-data')

    sql =   f"""
            INSERT INTO {db_table} (AWSAccountId, UserEmail, CreationDate, AMIId, ParentId)
            VALUES ('{account_id}', '{user_email}', '{event_time}', '{ami_id}', '{parent_id}')
            """

    response = rds_data.execute_statement(
        resourceArn = cluster_arn,
        secretArn = secret_arn,
        database = db_name,
        sql = sql
        )

def write_to_mysql_db(account_id, user_email, event_time, ami_id, parent_id):
    sql =   f"""
            INSERT INTO {db_table} (AWSAccountId, UserEmail, CreationDate, AMIId, ParentId)
            VALUES ('{account_id}', '{user_email}', '{event_time}', '{ami_id}', '{parent_id}')
            """
    try:
        cursor = connection.cursor()
        cursor.execute(sql)
        connection.commit()
        print(cursor.rowcount, f"Record inserted successfully into {db_name}.{db_table} table.")
        cursor.close()

    except mysql.connector.Error as error:
        print("Failed to insert record into Laptop table {}".format(error))

    finally:
        if (connection.is_connected()):
            connection.close()
            print("MySQL connection is closed")



def filter_cloudtrail_events(event) -> bool:
    """
    This function checks the eventName field in CloudTrail to see if it matches
    any of the event names in the EVENT_NAMES list.
    """
    if (event['eventName']) in EVENT_NAMES:
        return True
    return False

def insert_required_fields(cloudtrail_event):
    for item in cloudtrail_event:
        account_id = item['userIdentity']['accountId']
        user_email = item['userIdentity']['principalId'].split(':')[1]
        event_time = datetime.strptime(item['eventTime'], '%Y-%m-%dT%H:%M:%SZ')
        event_name = item['eventName']
        ami_id = item['responseElements']['imageId']
        parent_id = item['requestParameters']['instanceId']
        #write_to_aurora_db(account_id, user_email, event_time, ami_id, parent_id)
        write_to_mysql_db(account_id, user_email, event_time, ami_id, parent_id)

def print_required_fields(cloudtrail_event):
    for item in cloudtrail_event:
        account_id = item['userIdentity']['accountId']
        user_email = item['userIdentity']['principalId'].split(':')[1]
        event_time = datetime.strptime(item['eventTime'], '%Y-%m-%dT%H:%M:%SZ')
        event_name = item['eventName']
        ami_id = item['responseElements']['imageId']
        parent_id = item['requestParameters']['instanceId']
        print(f"User: {user_email}\nAWS Account Id: {account_id}\nEvent Time: {event_time}\nEvent Name:{event_name}\nNew AMI Id: {ami_id}\nParent Id: {parent_id}\n\n")


def lambda_cloudtrail_handler(event, context) -> None:
    """
    This functions processes CloudTrail logs from S3, filters events that are not AMI related, and writes to DB.
    :param event: List of S3 Events
    :param context: AWS Lambda Context Object
    :return: None
    """
    for record in event['Records']:
        # Get the object from the event and show its content type
        bucket = record['s3']['bucket']['name']
        key = urllib.parse.unquote_plus(record['s3']['object']['key'], encoding='utf-8')
        try:
            response = s3.get_object(Bucket=bucket, Key=key)
            content = response['Body'].read()

            with gzip.GzipFile(fileobj=io.BytesIO(content), mode='rb') as fh:
                event_json = json.load(fh)
                output_dict = [record for record in event_json['Records'] if filter_cloudtrail_events(record)]
                if len(output_dict) > 0:
                    insert_required_fields(output_dict)
        except Exception as e:
            print(e)
            message = f"""
                Error getting object {key} from bucket {bucket}.
                Make sure they exist and your bucket is in the same region as this function.
            """
            print(message)
            raise e

def unit_test() -> None:
    """
    This unit test can be run and requires a sample CloudTrail log file stored as text in the same path.
    """
    with open('sample_cloudtrail.txt') as json_file:
        event_json = json.load(json_file)
        output_dict = [record for record in event_json['Records'] if filter_cloudtrail_events(record)]
        if len(output_dict) > 0:
            insert_required_fields(output_dict)
            print_required_fields(output_dict)

#unit_test()