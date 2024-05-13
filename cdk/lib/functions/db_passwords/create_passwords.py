import boto3
import os
import logging
from datetime import datetime
import base64
import json
import pymysql
# import psycopg2

from botocore.exceptions import ClientError

#
# Set up our logger so we see logs in CloudWatch
#
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def describe_secret(secret_name):
    client = boto3.client(service_name='secretsmanager')

    try:
        # Describe the secret to get its ARN
        describe_secret_response = client.describe_secret(SecretId=secret_name)
        secret_arn = describe_secret_response.get('ARN')
        logger.info(f"Secret ARN has found: {secret_arn}")

        if not secret_arn:
            logger.error(f"Secret ARN not found for secret name: {secret_name}")
            return {
                'statusCode': 503,
                'body': 'No secret ARN received for DB admin'
            }

        logger.info(f"Secret ARN: {secret_arn}")

        # Now you can use the secret ARN to get the secret value
        get_secret_value_response = client.get_secret_value(SecretId=secret_arn)

        # Check if the secret value was returned
        if 'SecretString' in get_secret_value_response:
            logger.info("Successfully retrieved secret string")
            secret_string = get_secret_value_response['SecretString']
            # Process the secret string as needed
            return secret_string
        else:
            logger.warning("No SecretString in response")
            return {
                'statusCode': 503,
                'body': 'No SecretString in response from ARN DB admin'
            }

    except ClientError as e:
        logger.error(f"An error occurred: {e}")
        # raise e
        return {
            'statusCode': 503,
            'body': f"An error occurred: {e}"
        }


# def get_secret(region_name, secret_name):
def get_secret(secret_arn):
    logger.debug(f"Get secret function has started")
    # Create a Secrets Manager client
    # session = boto3.session.Session()
    client = boto3.client(service_name='secretsmanager')

    # Print client configuration information
    logger.debug("Client Info:")
    logger.debug("Service Name: %s", client.meta.service_model.service_name)
    logger.debug("Region Name: %s", client.meta.region_name)
    logger.debug("Endpoint URL: %s", client.meta.endpoint_url)
    logger.debug("Client Configuration: %s", client.meta.config)

    try:
        logger.info(f"Before get secret value: Secret ARN: {secret_arn}")
        # Now you can use the secret ARN to get the secret value
        get_secret_value_response = client.get_secret_value(SecretId=secret_arn)

        # Check if the secret value was returned
        if 'SecretString' in get_secret_value_response:
            logger.debug("Successfully retrieved secret string")
            secret = get_secret_value_response['SecretString']
        else:
            # For binary secrets, decode them before using
            secret = get_secret_value_response['SecretBinary'].decode('utf-8')

        return secret

    except ClientError as e:
        logger.error(f"An error occurred: {e}")
        # raise e
        return {
            'statusCode': 503,
            'body': f"An error occurred: {e}"
        }


def create_database_user(engine, host, admin_user, admin_password, user_name, user_password, granular_permissions):
    if engine == "mysql":
        connection = pymysql.connect(
            host=host,
            user=admin_user,
            password=admin_password
        )
        cursor = connection.cursor()

        # Create user
        # This should take user_name as input and password can be from a secured source
        logger.info(f"CREATE USER '{user_name}'@'%' IDENTIFIED BY '{user_password}'")
        cursor.execute(f"CREATE USER '{user_name}'@'%' IDENTIFIED BY '{user_password}'")

        # Grant privileges
        for permission in granular_permissions:
            database = permission['database']
            tables = permission['tables']
            grants = ','.join(permission['grants'])

            # Example
            # user_list: [{'application': 'director',
            # 'user_name': 'director_svc',
            #
            # 'granular_db_permissions': [
            #     {'database': 'canopy', 'tables': ['ivr_phone_number'], 'grants': ['SELECT']}]},
            #             {'application': 'uberapp', 'user_name': 'uberapp_svc',
            #              'granular_db_permissions': [{'database': 'canopy', 'tables': [], 'grants': ['SELECT']},
            #                                          {'database': 'uberapp', 'tables': [], 'grants': ['SELECT']}]}]
            #

            # Add MySQL grants
            # If the tables list is empty, use {database}.* to grant privileges on the entire database
            if len(tables) == 0:
                logger.info(f"GRANT {grants} ON {database}.* TO '{user_name}'@'%'")
                cursor.execute(f"GRANT {grants} ON {database}.* TO '{user_name}'@'%'")
            else:
                for table in tables:
                    full_table_name = f"{database}.{table}"
                    logger.info(f"GRANT {grants} ON {full_table_name} TO '{user_name}'@'%'")
                    cursor.execute(f"GRANT {grants} ON {full_table_name} TO '{user_name}'@'%'")

    cursor.execute("FLUSH PRIVILEGES")
    cursor.close()
    connection.close()


# elif engine == "postgres":
#     connection = psycopg2.connect(
#         dbname=db_name,
#         user=user,
#         password=password,
#         host=host
#     )
#     cursor = connection.cursor()
#     # Create user
#     cursor.execute(f"CREATE USER {user} WITH PASSWORD '{password}'")
#     # Grant privileges
#     for permission in granular_permissions:
#         database = permission['database']
#         tables = ','.join(permission['tables'])
#         grants = ','.join(permission['grants'])
#         cursor.execute(f"GRANT {grants} ON ALL TABLES IN SCHEMA {database} TO {user}")
#     cursor.close()
#     connection.commit()
#     connection.close()


def lambda_handler(event, context):

    logger.info(f"lambda_handler(): BEGIN")
    logger.debug(f"Event handler: {event}")

    # Load Secret from Secrets Manager
    secret_name = os.environ.get('ADMIN_DB_PASSWORD_SECRET_ARN')
    logger.debug(f"Secret name: {secret_name}")

    # IF EVENT PAYLOAD
    user_data = event.get('User')
    # FOR TEST
    #user_data = "eyJhcHBsaWNhdGlvbiI6ICJ1YmVyYXBwIiwgInVzZXJfbmFtZSI6ICJ1YmVyYXBwX3N2YyIsICJncmFudWxhcl9kYl9wZXJtaXNzaW9ucyI6IFt7ImRhdGFiYXNlIjogImNhbm9weSIsICJ0YWJsZXMiOiBbXSwgImdyYW50cyI6IFsiU0VMRUNUIl19LCB7ImRhdGFiYXNlIjogInViZXJhcHAiLCAidGFibGVzIjogW10sICJncmFudHMiOiBbIlNFTEVDVCJdfV19\\"

    if user_data:
        try:
            user_json = base64.b64decode(user_data).decode('utf-8')
            user = json.loads(user_json)
            logger.info("User: " + json.dumps(user, indent=2))
        except (TypeError, json.JSONDecodeError, UnicodeDecodeError) as e:
            logger.error("Failed to decode and parse user data:", e)
            return {
                'statusCode': 400,
                'body': 'Invalid user data format'
            }
    else:
        logger.error("No user data found in the event payload")
        return {
            'statusCode': 400,
            'body': 'No user data found in the event payload'
        }

    # Find admin credential
    secret = get_secret(secret_name)
    secret_dict = json.loads(secret)

    # Retrieve necessary variables from the secret
    db_engine = secret_dict['engine']
    db_host = secret_dict['host']
    admin_user = secret_dict['username']
    admin_password = secret_dict['password']

    logger.debug(f"db_engine: {db_engine}")
    logger.debug(f"db_host: {db_host}")

    # # Decode USER_LIST from Base64
    # user_json = base64.b64decode(user_base64).decode('utf-8')
    # user = json.loads(user_json)
    #
    # logger.debug(f"user_list_json: {user_json}")
    # logger.debug(f"user_list: {user}")

    # Establish connection to the RDS instance
    connection = None
    try:
        if db_engine == "mysql":
            connection = pymysql.connect(
                host=db_host,
                user=admin_user,
                password=admin_password
            )
        # elif db_engine == "postgresql":
        #     connection = psycopg2.connect(
        #         dbname='TODO_DB_NAME',
        #         user=db_user,
        #         password=db_password,
        #         host=db_host
        #     )

        if connection is not None:
            logger.debug("Application: %s", user['application'])
            logger.debug("User Name: %s", user['user_name'])
            logger.debug("Granular DB Permissions:")

            # Find user secret arn by a secret name
            user_secret_name = f"/infra/{user['application']}/{user['user_name']}/rds/credential"
            user_secret_arn = describe_secret(user_secret_name)
            logger.debug(f"user_secret_arn: {user_secret_arn}")

            if user_secret_arn is not None:
                user_secret_dict = json.loads(user_secret_arn)
                user['password'] = user_secret_dict['password']
                logger.debug(f"user_password: {user['password']}")

                for permission in user['granular_db_permissions']:
                    logger.debug("\tDatabase: %s", permission['database'])
                    logger.debug("\tTables: %s", permission['tables'])
                    logger.debug("\tGrants: %s", permission['grants'])

                # Create database user and grant permissions
                create_database_user(
                    db_engine,
                    db_host,
                    admin_user,
                    admin_password,
                    user['user_name'],
                    user['password'],
                    user['granular_db_permissions']
                )
            else:
                return {
                    'statusCode': 503,
                    'body': f"RDS DB connection error"
                }

    finally:
        # Close the connection if it's not None
        if connection is not None:
            connection.close()

    return {
        'statusCode': 200,
        'body': 'Environment variables read successfully'
    }
