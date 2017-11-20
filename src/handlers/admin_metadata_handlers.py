import os
import sys
import logging
import boto3
from boto3.dynamodb.conditions import Key
import json
import urllib
from helpers import web_helpers
import settings

# Set Logging Level
logger = logging.getLogger()
logger.setLevel(logging.ERROR)


def create_metadata_handler(event, context):
    try:
        # Interpret and validate request body
        body = json.loads(event["body"])

        if "name" not in body:
            raise Exception("'name' must be provided in 'parameters to generate a JWT token.")

        # Define item
        item = {'name': body["name"]}

        if 'isni' in body:
            item['isni'] = body['isni']

        if 'grid' in body:
            item['grid'] = body['grid']

        # Initialise DynamoDB
        dynamodb = boto3.resource('dynamodb')
        provider_table = dynamodb.Table(os.environ["METADATA_TABLE"])

        # Send Dynamo DB put response
        provider_table.put_item(Item=item)
        return web_helpers.generate_web_body_response('200', item)

    except:
        logger.error('Unexpected error: {}'.format(sys.exc_info()[0]))
        return web_helpers.generate_web_body_response(
            '400',
            {'message': "Incorrect path parameter type formatting for provider name. Ensure it is a URL encoded string"}
        )


def update_metadata_handler(event, context):
    try:
        name = urllib.unquote(urllib.unquote(event["pathParameters"]["name"]))

    except:
        logger.error('Unable to validate provider name: {}'.format(sys.exc_info()[0]))
        return web_helpers.generate_web_body_response(
            '400',
            {'message': "Incorrect path parameter type formatting for provider name. Ensure it is a URL encoded string"}
        )

    try:
        # Interpret and validate request body
        body = json.loads(event["body"])

        if 'isni' not in body or 'grid' not in body:
            raise Exception("'isni' and 'grid' must be provided.")

        dynamodb = boto3.resource('dynamodb')
        provider_table = dynamodb.Table(os.environ["METADATA_TABLE"])

        # Update meta values
        update_response = provider_table.update_item(
            Key={'name': name},
            UpdateExpression="set isni = :i, grid = :g",
            ExpressionAttributeValues={
                ':i': body['isni'],
                ':g': body['grid']
            },
            ReturnValues="ALL_NEW"
        )

        return web_helpers.generate_web_body_response('200', update_response["Attributes"])

    except:
        logger.error('Unexpected error: {}'.format(sys.exc_info()[0]))
        return web_helpers.generate_web_body_response(
            '400',
            {'message': "Incorrect path parameter formatting for provider name. Ensure it is a URL encoded string."}
        )


def delete_metadata_handler(event, context):
    try:
        name = urllib.unquote(urllib.unquote(event["pathParameters"]["name"]))

    except:
        logger.error('Unable to validate provider name: {}'.format(sys.exc_info()[0]))
        return web_helpers.generate_web_body_response(
            '400',
            {'message': "Incorrect path parameter type formatting for provider name. Ensure it is a URL encoded string"}
        )

    try:
        dynamodb = boto3.resource('dynamodb')
        provider_table = dynamodb.Table(os.environ["METADATA_TABLE"])
        provider_table.delete_item(Key={'name': name})
        return web_helpers.generate_web_body_response('200', {'message': "Successfully deleted provider."})

    except:
        logger.error('Unexpected error: {}'.format(sys.exc_info()[0]))
        return web_helpers.generate_web_body_response(
            '400',
            {'message': "Incorrect path parameter formatting for provider name. Ensure it is a URL encoded string."}
        )


def get_metadata_handler(event, context):
    try:
        name = urllib.unquote(urllib.unquote(event["pathParameters"]["name"]))

        # Initialise DynamoDB
        dynamo_db = boto3.resource('dynamodb')
        provider_table = dynamo_db.Table(os.environ["METADATA_TABLE"])

        # Check if provider meta data exists
        query_response = provider_table.query(KeyConditionExpression=Key('name').eq(name))

        if query_response["Count"] != 1:
            return web_helpers.generate_web_body_response(
                '404',
                {'message': "Provider '{}' has no meta data.".format(name)}
            )

        # Assign raid item to single item, since the result will be an array of one item
        provider_metadata = query_response['Items'][0]

        return web_helpers.generate_web_body_response('200', provider_metadata)


    except:
        logger.error('Unable to validate provider name: {}'.format(sys.exc_info()[0]))
        return web_helpers.generate_web_body_response(
            '400',
            {'message': "Incorrect path parameter formatting for provider name. Ensure it is a URL encoded string."}
        )


def get_service_points_handler(event, context):
    try:
        query_parameters = {
            'IndexName': 'type',
            'KeyConditionExpression': Key('type').eq(settings.SERVICE_ROLE)
        }

        return web_helpers.generate_table_list_response(event, query_parameters, os.environ["METADATA_TABLE"])

    except:
        logger.error('Unable to get service points: {}'.format(sys.exc_info()[0]))
        return web_helpers.generate_web_body_response(
            '400',
            {'message': "Unable to get service points."}
        )


def get_institution_handler(event, context):
    try:
        query_parameters = {
            'IndexName': 'type',
            'KeyConditionExpression': Key('type').eq(settings.INSTITUTION_ROLE)
        }

        return web_helpers.generate_table_list_response(event, query_parameters, os.environ["METADATA_TABLE"])

    except:
        logger.error('Unable to get institutions: {}'.format(sys.exc_info()[0]))
        return web_helpers.generate_web_body_response(
            '400',
            {'message': "Unable to get institutions."}
        )
