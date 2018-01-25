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
        name = urllib.unquote(urllib.unquote(event["pathParameters"]["name"]))

        # Get current datetime
        now = datetime.datetime.now().isoformat()

        # Interpret and validate request body
        body = json.loads(event["body"])

        # Get environment
        if "environment" in body \
                and (body["environment"] == settings.DEMO_ENVIRONMENT
                     or body["environment"] == settings.LIVE_ENVIRONMENT):
            environment = body["environment"]
        else:
            return web_helpers.generate_web_body_response(
                '400',
                {'message': "Unable to create a entity token. 'environment' must be provided in the body of the"
                            " request and have the value 'demo' or 'live'"}
            )

        # Initialise DynamoDB
        dynamodb = boto3.resource('dynamodb')
        token_table = dynamodb.Table(os.environ["TOKEN_TABLE"])
        metadata_table = dynamodb.Table(os.environ["METADATA_TABLE"])

        # Check if metadata exists
        query_response = metadata_table.query(KeyConditionExpression=Key('name').eq(name))

        if query_response["Count"] != 1:
            return web_helpers.generate_web_body_response(
                '404',
                {'message': "Entity '{}' has no metadata.".format(name)}
            )

        # Assign metadata item to single item, since the result will be an array of one item
        metadata = query_response['Items'][0]


        # Create JWT token
        jwt = auth.jwt_role_encode(JWT_SECRET, JWT_AUDIENCE, JWT_ISSUER, name, metadata['type'], environment, 24)

        # Define item
        item = {'name': name, 'dateCreated': str(now), 'token': jwt, 'environment': environment}

        # Send Dynamo DB put response
        token_table.put_item(Item=item)

        return web_helpers.generate_web_body_response('200', item)

    except Exception, e:
        logger.error('Unexpected error: {}'.format(sys.exc_info()[0]))
        return web_helpers.generate_web_body_response(
            '400',
            {'message': "Unable to create an entity token. 'environment' must be provided in the body of the request"} #TODO
        )


def delete_key_handler(event, context):
    try:
        name = urllib.unquote(urllib.unquote(event["pathParameters"]["name"]))
        date_created = urllib.unquote(urllib.unquote(event["pathParameters"]["datetime"]))

        # Initialise DynamoDB
        dynamodb = boto3.resource('dynamodb')
        token_table = dynamodb.Table(os.environ["TOKEN_TABLE"])
        token_table.delete_item(Key={'name': name, 'dateCreated': date_created})
        return web_helpers.generate_web_body_response('200', {'message': "Successfully deleted an entity token."})

    except:
        logger.error('Unexpected error: {}'.format(sys.exc_info()[0]))
        return web_helpers.generate_web_body_response(
            '400',
            {'message': "Incorrect path parameter formatting for an entity name or date. Ensure it is a URL encoded string."}
        )


def get_keys_handler(event, context):
    try:
        name = urllib.unquote(urllib.unquote(event["pathParameters"]["name"]))

        query_parameters = {'KeyConditionExpression': Key('name').eq(name)}

        return web_helpers.generate_table_list_response(event, query_parameters, os.environ["TOKEN_TABLE"])

    except:
        logger.error('Unable to validate entity name: {}'.format(sys.exc_info()[0]))
        return web_helpers.generate_web_body_response(
            '400',
            {'message': "Incorrect path parameter type formatting for entity name. Ensure it is a URL encoded string"}
        )

