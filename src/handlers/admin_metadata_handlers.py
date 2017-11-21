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

        if "name" not in body \
                or "type" not in body \
                or (body["type"] != settings.SERVICE_ROLE and body["type"] != settings.INSTITUTION_ROLE):
            return web_helpers.generate_web_body_response(
                '400',
                {
                    'message': "Incorrect parameters or format."}
            )

        # Define item
        item = {'name': body["name"], 'type': body["type"]}

        if 'isni' in body:
            item['isni'] = body['isni']

        if 'grid' in body:
            item['grid'] = body['grid']

        # Initialise DynamoDB
        dynamodb = boto3.resource('dynamodb')
        metadata_table = dynamodb.Table(os.environ["METADATA_TABLE"])

        # Send Dynamo DB put response
        metadata_table.put_item(Item=item)
        return web_helpers.generate_web_body_response('200', item)

    except:
        logger.error('Unexpected error: {}'.format(sys.exc_info()[0]))
        return web_helpers.generate_web_body_response(
            '500',
            {'message': "Unknown error has occurred."}
        )


def update_metadata_handler(event, context):
    try:
        name = urllib.unquote(urllib.unquote(event["pathParameters"]["name"]))

        # Interpret and validate request body
        body = json.loads(event["body"])

        # Initialise DynamoDB
        dynamo_db = boto3.resource('dynamodb')
        metadata_table = dynamo_db.Table(os.environ["METADATA_TABLE"])

        # Check if metadata exists
        query_response = metadata_table.query(KeyConditionExpression=Key('name').eq(name))
        if query_response["Count"] != 1:
            return web_helpers.generate_web_body_response(
                '404',
                {'message': "Entity '{}' has no metadata.".format(name)}
            )

        # Build update dictionary
        update_values_list = []
        expression_attribute_values = {}

        if 'isni' in body:
            update_values_list.append("isni = :i")
            expression_attribute_values[':i'] = body['isni']

        if 'grid' in body:
            update_values_list.append("grid = :g")
            expression_attribute_values[':g'] = body['grid']

        # Update meta values
        update_response = metadata_table.update_item(
            Key={'name': name},
            UpdateExpression='set {}'.format(", ".join(update_values_list)),
            ExpressionAttributeValues=expression_attribute_values,
            ReturnValues="ALL_NEW"
        )

        return web_helpers.generate_web_body_response('200', update_response["Attributes"])

    except:
        logger.error('Unexpected error: {}'.format(sys.exc_info()[0]))
        return web_helpers.generate_web_body_response(
            '400',
            {'message': "Incorrect path parameter formatting for entity name. Ensure it is a URL encoded string."}
        )


def delete_metadata_handler(event, context):
    try:
        name = urllib.unquote(urllib.unquote(event["pathParameters"]["name"]))

        # Initialise DynamoDB
        dynamo_db = boto3.resource('dynamodb')
        metadata_table = dynamo_db.Table(os.environ["METADATA_TABLE"])

        # Check if metadata exists
        query_response = metadata_table.query(KeyConditionExpression=Key('name').eq(name))
        if query_response["Count"] != 1:
            return web_helpers.generate_web_body_response(
                '404',
                {'message': "Entity '{}' has no metadata.".format(name)}
            )

        metadata_table.delete_item(Key={'name': name})
        return web_helpers.generate_web_body_response('200', {'message': "Successfully deleted entity metadata."})

    except:
        logger.error('Unexpected error: {}'.format(sys.exc_info()[0]))
        return web_helpers.generate_web_body_response(
            '400',
            {'message': "Incorrect path parameter formatting for entity name. Ensure it is a URL encoded string."}
        )


def get_metadata_handler(event, context):
    try:
        name = urllib.unquote(urllib.unquote(event["pathParameters"]["name"]))

        # Initialise DynamoDB
        dynamo_db = boto3.resource('dynamodb')
        metadata_table = dynamo_db.Table(os.environ["METADATA_TABLE"])

        # Check if metadata exists
        query_response = metadata_table.query(KeyConditionExpression=Key('name').eq(name))

        if query_response["Count"] != 1:
            return web_helpers.generate_web_body_response(
                '404',
                {'message': "Entity '{}' has no metadata.".format(name)}
            )

        # Assign metadata item to single item, since the result will be an array of one item
        metadata = query_response['Items'][0]

        return web_helpers.generate_web_body_response('200', metadata)


    except:
        logger.error('Unable to validate entity name: {}'.format(sys.exc_info()[0]))
        return web_helpers.generate_web_body_response(
            '400',
            {'message': "Incorrect path parameter formatting for entity name. Ensure it is a URL encoded string."}
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
