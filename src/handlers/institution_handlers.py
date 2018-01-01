import os
import sys
import logging
import datetime
import boto3
from boto3.dynamodb.conditions import Key, Attr
import json
import urllib
from helpers import web_helpers
import settings


# Set Logging Level
logger = logging.getLogger()
logger.setLevel(logging.ERROR)


def get_institutions_handler(event, context):
    """
    Return providers in metadata
    :param event:
    :param context:
    :return:
    """

    query_parameters = {
        'IndexName': 'type',
        'ProjectionExpression': "#n, grid, isni",
        'ExpressionAttributeNames': {"#n": "name"},
        'KeyConditionExpression': Key('type').eq(settings.INSTITUTION_ROLE)
    }

    return web_helpers.generate_table_list_response(event, query_parameters, os.environ["METADATA_TABLE"])


def get_raid_institutions_handler(event, context):
    """
    Return providers associated to the institution in the path with optional parameters for filter and search options
    :param event:
    :param context:
    :return:
    """
    try:
        raid_handle = urllib.unquote(urllib.unquote(event["pathParameters"]["raidId"]))

    except:
        logger.error('Unable to validate RAiD parameter: {}'.format(sys.exc_info()[0]))
        return web_helpers.generate_web_body_response('400', {
            'message': "Incorrect path parameter type formatting for RAiD handle. Ensure it is a URL encoded string"}, event)

    institution_query_parameters = {
        'IndexName': 'HandleTypeIndex',
        'ProjectionExpression': "#n, startDate, endDate",
        'ExpressionAttributeNames': {"#n": "name"},
        'KeyConditionExpression': Key('handle-type').eq('{}-{}'.format(
            raid_handle, settings.INSTITUTION_ROLE))
    }

    return web_helpers.generate_table_list_response(
        event, institution_query_parameters,
        settings.get_environment_table(
            settings.ASSOCIATION_TABLE,
            event['requestContext']['authorizer']['environment'])
    )


def create_raid_institution_association_handler(event, context):
    """
    Create a new institution association to a RAiD
    :param event:
    :param context:
    :return:
    """
    try:
        raid_handle = urllib.unquote(urllib.unquote(event["pathParameters"]["raidId"]))
    except:
        logger.error('Unable to validate RAiD parameter: {}'.format(sys.exc_info()[0]))
        return web_helpers.generate_web_body_response('400', {
            'message': "Incorrect path parameter type formatting for RAiD handle. Ensure it is a URL encoded string"}, event)

    try:
        environment = event['requestContext']['authorizer']['environment']

        # Initialise DynamoDB
        dynamo_db = boto3.resource('dynamodb')
        raid_table = dynamo_db.Table(
            settings.get_environment_table(settings.RAID_TABLE, environment)
        )

        # Check if RAiD exists
        query_response = raid_table.query(KeyConditionExpression=Key('handle').eq(raid_handle))

        if query_response["Count"] != 1:
            return web_helpers.generate_web_body_response('400', {
                'message': "Invalid RAiD handle provided in parameter path. "
                           "Ensure it is a valid RAiD handle URL encoded string"}, event)

        # Assign raid item to single item, since the result will be an array of one item
        raid_item = query_response['Items'][0]

        # Interpret and validate request body
        body = json.loads(event["body"])

        if "startDate" in body:
            try:
                start_date = datetime.datetime.strptime(body["startDate"], "%Y-%m-%d %H:%M:%S")
            except ValueError as e:
                logger.error('Unable to capture date: {}'.format(e))
                return web_helpers.generate_web_body_response('400', {
                    'message': "Incorrect date format, should be yyyy-MM-dd hh:mm:ss"}, event)

        else:
            # Get current datetime
            start_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if "name" not in body:
            return web_helpers.generate_web_body_response('400', {
                'message': "'name' must be provided in your request body to create an association"}, event)

        # Define institution item
        institution_item = {
            'handle': raid_handle,
            'startDate': start_date,
            'name': body['name'],
            'raidName': raid_item['meta']['name'],
            'type': settings.INSTITUTION_ROLE,
            'handle-name': '{}-{}'.format(raid_handle, body['name']),
            'handle-type': '{}-{}'.format(raid_handle, settings.INSTITUTION_ROLE)
        }

        # Send Dynamo DB put for new RAiD association

        # Send Dynamo DB put for new association
        association_index_table = dynamo_db.Table(
            settings.get_environment_table(
                settings.ASSOCIATION_TABLE, environment
            )
        )
        association_index_table.put_item(Item=institution_item)

        return web_helpers.generate_web_body_response('200', {
                        'name': institution_item['name'],
                        'startDate': institution_item['startDate']
                    }, event)

    except:
        logger.error('Unable to create an institution to a RAiD association: {}'.format(sys.exc_info()[0]))
        return web_helpers.generate_web_body_response('500', {
            'message': "Unable to perform request due to error. Please check structure of the body."}, event)


def end_raid_institution_association_handler(event, context):  # TODO
    """
    End a institution association to a RAiD
    :param event:
    :param context:
    :return:
    """
    try:
        raid_handle = urllib.unquote(urllib.unquote(event["pathParameters"]["raidId"]))

    except:
        logger.error('Unable to validate RAiD parameter: {}'.format(sys.exc_info()[0]))
        return web_helpers.generate_web_body_response('400', {
            'message': "Incorrect path parameter type formatting for RAiD handle. Ensure it is a URL encoded string"}, event)

    try:
        environment = event['requestContext']['authorizer']['environment']

        # Initialise DynamoDB
        dynamo_db = boto3.resource('dynamodb')
        raid_table = dynamo_db.Table(
            settings.get_environment_table(settings.RAID_TABLE, event['requestContext']['authorizer']['environment'])
        )

        # Check if RAiD exists
        query_response = raid_table.query(KeyConditionExpression=Key('handle').eq(raid_handle))

        if query_response["Count"] != 1:
            return web_helpers.generate_web_body_response('400', {
                'message': "Invalid RAiD handle provided in parameter path. "
                           "Ensure it is a valid RAiD handle URL encoded string"}, event)

        # Interpret and validate request body
        body = json.loads(event["body"])

        if "endDate" in body:
            try:
                end_date = datetime.datetime.strptime(body["endDate"], "%Y-%m-%d %H:%M:%S")
            except ValueError as e:
                logger.error('Unable to capture date: {}'.format(e))
                return web_helpers.generate_web_body_response('400', {
                    'message': "Incorrect date format, should be yyyy-MM-dd hh:mm:ss"}, event)
        else:
            # Get current datetime
            end_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if "name" not in body:
            return web_helpers.generate_web_body_response('400', {
                'message': "'name' must be provided in your request body to end an association"}, event)

        # Update DynamoDB put to end association
        association_index_table = dynamo_db.Table(
            settings.get_environment_table(
                settings.ASSOCIATION_TABLE, environment
            )
        )

        existing_institution_query_parameters = {
            'IndexName': 'HandleNameIndex',
            'ProjectionExpression': "startDate, endDate",
            'FilterExpression': Attr('endDate').not_exists(),
            'KeyConditionExpression': Key('handle-name').eq('{}-{}'.format(raid_handle, body['name']))
        }

        institution_query_response = association_index_table.query(**existing_institution_query_parameters)
        existing_institution = institution_query_response["Items"][0]

        # Get existing item
        update_response = association_index_table.update_item(
            Key={
                'startDate': existing_institution['startDate'],
                'handle': raid_handle
            },
            UpdateExpression="set endDate = :e",
            ExpressionAttributeValues={
                ':e': end_date
            },
            ReturnValues="ALL_NEW"
        )

        return web_helpers.generate_web_body_response('200', {
            'name': body['name'],
            'startDate': existing_institution['startDate'],
            'endDate': end_date
        }, event)
    except:
        logger.error('Unable to end a institution to a RAiD association: {}'.format(sys.exc_info()[0]))
        return web_helpers.generate_web_body_response('500', {
            'message': "Unable to perform request due to error. Please check structure of the body."}, event)
