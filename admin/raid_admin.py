from __future__ import print_function

import os
import sys
import re
import logging
import datetime
import jwt
import boto3

# Roles
INSTITUTION_ROLE = "institution"
SERVICE_ROLE = "service"

# Token issuing
JWT_ISSUER = os.environ["JWT_ISSUER"]
JWT_AUDIENCE = os.environ["JWT_AUDIENCE"]
JWT_SECRET = os.environ["JWT_SECRET"]

#Dynamo DB
INSTITUTION_TABLE = os.environ["INSTITUTION_TABLE"]

# Set Logging Level
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def jwt_role_encode(jwt_secret, jwt_audience, jwt_issuer, subject, role, months=6):
    """
    Generate a JWT token for a subject that will last a number months of months after the current date.
    :param jwt_secret: String used for encrypted JWT signature 
    :param jwt_audience: Target site the JWT token will be authenticated against
    :param jwt_issuer: Organisation name of the principal issuer
    :param subject: Identifying attribute for the JWT token subject 
    :param role: Must be either 'service' or 'role'
    :param months: Number of months the token should expire from the current date
    :return: JWT Token
    """
    try:
        # Validate role type
        if role != INSTITUTION_ROLE and role != SERVICE_ROLE:
            raise Exception('Invalid RAiD JWT role type: {}'.format(role))

        # Calculate future expiration date
        future_date = datetime.date.today() + datetime.timedelta(months*365/12)

        # Generate payload and token
        payload = {
            'sub': subject,
            'aud': jwt_audience,
            'iss': jwt_issuer,
            'iat': datetime.datetime.now(),
            'exp': datetime.datetime.combine(future_date, datetime.time.min),
            'role': role
        }
        token = jwt.encode(payload, jwt_secret)
        return token
    except:
        logger.error("JWT encoding error: {}".format(sys.exc_info()[0]))
        raise


def institution_crud_handler(event, context):
    """
    CRUD handler for institutions table
    :param event: 
    :param context: 
    :return: 
    """
    try:
        logger.info('Institution CRUD Event={}'.format(event))

        # validate event
        if "query" not in event or "parameters" not in event:
            raise Exception("Event must contain the institution 'query' and 'parameters'.")

        # Initialise DynamoDB
        dynamodb = boto3.resource('dynamodb')
        institution_table = dynamodb.Table(INSTITUTION_TABLE)

        # Create new item
        if event["query"] == "create":
            # Validate parameter existence
            if "name" not in event["parameters"] or "grid" not in event["parameters"]:
                raise Exception("'name' and 'grid' must be provided in 'parameters to generate a JWT token.")

            # TODO regex validate grid id 'grid.[NUMERIC].[ALPHANUMERIC]'

            # Get current datetime
            now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Create JWT token
            jwt = jwt_role_encode(JWT_SECRET, JWT_AUDIENCE, JWT_ISSUER, event["parameters"]["grid"], INSTITUTION_ROLE,
                                  24)

            # Define item
            item = {
                    'Name': event["parameters"]["name"],
                    'Grid': event["parameters"]["grid"],
                    'Date': now,
                    'Token': jwt
            }

            # Send Dynamo DB put response
            institution_table.put_item(Item=item)

            return item

        # Use existing item
        elif event["query"] == "update" or event["query"] == "read" or event["query"] == "delete":
            # Validate required item key values
            if "grid" not in event["parameters"] or "date" not in event["parameters"]:
                raise Exception("Key fields 'grid' and 'date' must be provided in 'parameters' for this query.")

            if event["query"] == "update":
                update_response = institution_table.update_item(
                    Key={
                        'Grid': event["parameters"]["grid"],
                        'Date': event["parameters"]["date"]
                    },
                    UpdateExpression="set #token = :t",
                    ExpressionAttributeValues={
                        ':t': jwt_role_encode(JWT_SECRET, JWT_AUDIENCE, JWT_ISSUER, event["parameters"]["grid"],
                                              INSTITUTION_ROLE, 24)
                    },
                    ExpressionAttributeNames={
                        '#token': "Token",
                    },
                    ReturnValues="UPDATED_NEW"
                )

                return update_response["Attributes"]

            elif event["query"] == "read":
                read_response = institution_table.get_item(
                    Key={
                        'Grid': event["parameters"]["grid"],
                        'Date': event["parameters"]["date"]
                    }
                )

                if "Item" not in read_response:
                    raise Exception("No item found matching provided keys.")

                return read_response["Item"]

            elif event["query"] == "delete":
                if "grid" not in event["parameters"] or "date" not in event["parameters"]:
                    raise Exception("'grid' and 'date' must be provided in 'parameters to generate a new JWT token.")

                delete_response = institution_table.delete_item(
                    Key={
                        'Grid': event["parameters"]["grid"],
                        'Date': event["parameters"]["date"]
                    }
                )

        else:
            raise Exception("Invalid query type '{}'."
                            " Only 'create', 'update', 'read', and 'delete' may be used.".format(event["query"]))
    except:
        logger.error('Unexpected error: {}'.format(sys.exc_info()[0]))
        raise

