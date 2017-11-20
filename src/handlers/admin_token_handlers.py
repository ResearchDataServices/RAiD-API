import os
import sys
import json
import logging
import datetime
import urllib
import boto3
from boto3.dynamodb.conditions import Key, Attr
from helpers import web_helpers
import auth
import settings


# Token issuing
JWT_ISSUER = os.environ["JWT_ISSUER"]
JWT_AUDIENCE = os.environ["JWT_AUDIENCE"]
JWT_SECRET = os.environ["JWT_SECRET"]

# Set Logging Level
logger = logging.getLogger()
logger.setLevel(logging.ERROR)


def create_key_handler(event, context):
    try:
        # Interpret and validate request body
        body = json.loads(event["body"])

        if "name" not in body:
            raise Exception("'name' must be provided in 'parameters to generate a JWT token.")

        # Get current datetime
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Get environment
        if "environment" in body:
            environment = body["environment"]
        else:
            environment = "demo"

        # Create JWT token
        jwt = auth.jwt_role_encode(JWT_SECRET, JWT_AUDIENCE, JWT_ISSUER, body["name"], settings.SERVICE_ROLE,
                                   environment, 24)

        # Define item
        item = {'Name': body["name"], 'Date': now, 'Token': jwt, 'environment': environment}

        # Initialise DynamoDB
        dynamodb = boto3.resource('dynamodb')
        provider_table = dynamodb.Table(os.environ["TOKEN_TABLE"])
        # Send Dynamo DB put response
        provider_table.put_item(Item=item)

        return web_helpers.generate_web_body_response('200', item)

    except:
        logger.error('Unexpected error: {}'.format(sys.exc_info()[0]))
        return web_helpers.generate_web_body_response(
            '400',
            {'message': "Unable to create a Provider token. 'name' must be provided in the body of the request"}
        )


def delete_key_handler(event, context):
    try:
        name = urllib.unquote(urllib.unquote(event["pathParameters"]["name"]))

    except:
        logger.error('Unable to validate provider name: {}'.format(sys.exc_info()[0]))
        return web_helpers.generate_web_body_response(
            '400',
            {'message': "Incorrect path parameter formatting for provider name. Ensure it is a URL encoded string."}
        )

    try:
        # Interpret and validate request body
        body = json.loads(event["body"])

        if "date" not in body:
            raise Exception("A valid 'date' must be provided in parameters to delete the JWT token.")

        # Initialise DynamoDB
        dynamodb = boto3.resource('dynamodb')
        provider_table = dynamodb.Table(os.environ["TOKEN_TABLE"])
        provider_table.delete_item(Key={'Name': name, 'Date': body["date"]})
        return web_helpers.generate_web_body_response('200', {'message': "Successfully deleted provider token."})

    except:
        logger.error('Unexpected error: {}'.format(sys.exc_info()[0]))
        return web_helpers.generate_web_body_response(
            '400',
            {'message': "A valid 'date' must be provided in parameters to delete the JWT token."}
        )


def get_keys_handler(event, context):
    try:
        name = urllib.unquote(urllib.unquote(event["pathParameters"]["name"]))

        query_parameters = {'KeyConditionExpression': Key('Name').eq(name)}

        return web_helpers.generate_table_list_response(event, query_parameters, os.environ["TOKEN_TABLE"])

    except:
        logger.error('Unable to validate provider name: {}'.format(sys.exc_info()[0]))
        return web_helpers.generate_web_body_response(
            '400',
            {'message': "Incorrect path parameter type formatting for provider name. Ensure it is a URL encoded string"}
        )

