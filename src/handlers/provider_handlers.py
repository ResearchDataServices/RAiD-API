import sys
import logging
import datetime
import boto3
from boto3.dynamodb.conditions import Key
import json
import urllib
from helpers import web_helpers
import settings


# Set Logging Level
logger = logging.getLogger()
logger.setLevel(logging.ERROR)


def get_raid_providers_handler(event, context):
    """
    Return providers associated to the raid in the path with optional parameters for filter and search options
    :param event:
    :param context:
    :return:
    """
    try:
        raid_handle = urllib.unquote(urllib.unquote(event["pathParameters"]["raidId"]))

    except:
        logger.error('Unable to validate RAiD parameter: {}'.format(sys.exc_info()[0]))
        return web_helpers.generate_web_body_response(
            '400',
            {'message': "Incorrect path parameter type formatting for RAiD handle. Ensure it is a URL encoded string"},
            event
        )

    query_parameters = {
        'IndexName': 'HandleProviderIndex',
        'KeyConditionExpression': Key('handle').eq(raid_handle)
    }

    return web_helpers.generate_table_list_response(
        event, query_parameters,
        settings.get_environment_table(settings.PROVIDER_TABLE, event['requestContext']['authorizer']['environment'])
    )


def create_raid_provider_association_handler(event, context):
    """
    Create a new provider association to a RAiD
    :param event:
    :param context:
    :return:
    """
    try:
        raid_handle = urllib.unquote(urllib.unquote(event["pathParameters"]["raidId"]))

    except:
        logger.error('Unable to validate RAiD parameter: {}'.format(sys.exc_info()[0]))
        return web_helpers.generate_web_body_response(
            '400',
            {'message': "Incorrect path parameter type formatting for RAiD handle. Ensure it is a URL encoded string"},
            event
        )

    try:
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

        # Insert association to provider index table
        provider_index_table = dynamo_db.Table(
            settings.get_environment_table(
                settings.PROVIDER_TABLE,
                event['requestContext']['authorizer']['environment'])
        )

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

        if "provider" not in body:
            return web_helpers.generate_web_body_response('400', {
                'message': "'provider' must be provided in your request body to create an association"}, event)

        # Define RAiD item
        service_item = {
            'provider': body['provider'],
            'handle': raid_handle,
            'startDate': start_date
        }

        # Send Dynamo DB put for new RAiD
        provider_index_table.put_item(Item=service_item)

        return web_helpers.generate_web_body_response('200', service_item, event)

    except:
        logger.error('Unable to associate a provider to a RAiD: {}'.format(sys.exc_info()[0]))
        return web_helpers.generate_web_body_response('500', {
            'message': "Unable to perform request due to error. Please check structure of the body."}, event)


def end_raid_provider_association_handler(event, context):
    """
    End a provider association to a RAiD
    :param event:
    :param context:
    :return:
    """
    try:
        raid_handle = urllib.unquote(urllib.unquote(event["pathParameters"]["raidId"]))

    except:
        logger.error('Unable to validate RAiD parameter: {}'.format(sys.exc_info()[0]))
        return web_helpers.generate_web_body_response(
            '400',
            {'message': "Incorrect path parameter type formatting for RAiD handle. Ensure it is a URL encoded string"},
            event
        )

    try:
        # Initialise DynamoDB
        dynamo_db = boto3.resource('dynamodb')
        raid_table = dynamo_db.Table(
            settings.get_environment_table(
                settings.RAID_TABLE,
                event['requestContext']['authorizer']['environment']
            )
        )

        # Check if RAiD exists
        query_response = raid_table.query(KeyConditionExpression=Key('handle').eq(raid_handle))

        if query_response["Count"] != 1:
            return web_helpers.generate_web_body_response('400', {
                'message': "Invalid RAiD handle provided in parameter path. "
                           "Ensure it is a valid RAiD handle URL encoded string"}, event)

        # Insert association to provider index table
        provider_index_table = dynamo_db.Table(
            settings.get_environment_table(
                settings.PROVIDER_TABLE,
                event['requestContext']['authorizer']['environment']
            )
        )

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

        if "provider" not in body:
            return web_helpers.generate_web_body_response('400', {
                'message': "'provider' must be provided in your request body to end an association"}, event)

        # Update provider association
        update_response = provider_index_table.update_item(
            Key={
                'provider': body['provider'],
                'handle': raid_handle
            },
            UpdateExpression="set endDate = :e",
            ExpressionAttributeValues={
                ':e': end_date
            },
            ReturnValues="ALL_NEW"
        )

        return web_helpers.generate_web_body_response('200', update_response["Attributes"], event)
    except:
        logger.error('Unable to end a provider to a RAiD association: {}'.format(sys.exc_info()[0]))
        return web_helpers.generate_web_body_response('500', {
            'message': "Unable to perform request due to error. Please check structure of the body."}, event)

