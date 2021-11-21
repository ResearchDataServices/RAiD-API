import sys
import logging
import boto3
from boto3.dynamodb.conditions import Key
import urllib.request, urllib.parse, urllib.error
from helpers import web_helpers
import settings

# Set Logging Level
logger = logging.getLogger()
logger.setLevel(logging.ERROR)


def get_raid_public_handler(event, context):
    """
    Show the existence of the RAiD and all public information metadata attached RAiDPublicModel
    :param event:
    :param context:
    :return:
    """
    try:
        raid_handle = urllib.parse.unquote(urllib.parse.unquote(event["pathParameters"]["raidId"]))

    except:
        logger.error('Unable to validate RAiD parameter: {}'.format(sys.exc_info()[0]))
        return web_helpers.generate_web_body_response(
            '400',
            {'message': "Incorrect path parameter type formatting for RAiD handle. Ensure it is a valid RAiD handle"
                        " URL encoded string"},
            event
        )

    try:
        # Check if demo or live environment
        if event["queryStringParameters"]:
            try:
                parameters = event["queryStringParameters"]
                if "demo" in parameters and (parameters["demo"] == 'True' or parameters["demo"] == 'true'):
                    table_name = settings.get_environment_table(settings.RAID_TABLE, 'demo')
                else:
                    table_name = settings.get_environment_table(settings.RAID_TABLE, 'live')
            except ValueError as e:
                logger.error('Incorrect parameter type formatting: {}'.format(e))
                return web_helpers.generate_web_body_response(
                    '400',
                    {'message': "Incorrect parameter type formatting."},
                    event
                )
        else:
            table_name = settings.get_environment_table(settings.RAID_TABLE, 'live')

        # Initialise DynamoDB
        dynamo_db = boto3.resource('dynamodb')
        raid_table = dynamo_db.Table(table_name)

        # Check if RAiD exists
        query_response = raid_table.query(KeyConditionExpression=Key('handle').eq(raid_handle))

        if query_response["Count"] != 1:
            return web_helpers.generate_web_body_response('404', {'message': "RAiD handle not found"}, event)

        # Assign raid item to single item, since the result will be an array of one item
        raid_item = query_response['Items'][0]

        public_raid_item = {
            "contentPath": raid_item["contentPath"],
            "handle": raid_item["handle"],
            "creationDate": raid_item["creationDate"]
        }

        return web_helpers.generate_web_body_response('200', public_raid_item)

    except:
        logger.error('Unable to get RAiD: {}'.format(sys.exc_info()[0]))
        return web_helpers.generate_web_body_response(
            '500',
            {'message': "Unable to fetch RAiD due to an error. Please check structure of the parameters."},
            event
        )


def redirect_raid_path_handler(event, context):
    """
    Redirect from a RAiD handle to it'c minted content path
    :param event:
    :param context:
    :return:
    """
    try:
        raid_handle = urllib.parse.unquote(urllib.parse.unquote(event["pathParameters"]["raidId"]))

    except:
        logger.error('Unable to validate RAiD parameter: {}'.format(sys.exc_info()[0]))
        return web_helpers.generate_web_body_response(
            '400', {'message': "Incorrect path parameter type formatting for RAiD handle. Ensure it is a valid RAiD"
                               " handle URL encoded string"},
            event
        )

    try:
        # Check if demo or live environment
        if event["queryStringParameters"]:
            try:
                parameters = event["queryStringParameters"]
                if "demo" in parameters and (parameters["demo"] == 'True' or parameters["demo"] == 'true'):
                    table_name = settings.get_environment_table(settings.RAID_TABLE, 'demo')
                else:
                    table_name = settings.get_environment_table(settings.RAID_TABLE, 'live')
            except ValueError as e:
                logger.error('Incorrect parameter type formatting: {}'.format(e))
                return web_helpers.generate_web_body_response(
                    '400', {'message': "Incorrect parameter type formatting."}, event
                )
        else:
            table_name = settings.get_environment_table(settings.RAID_TABLE, 'live')

        # Initialise DynamoDB
        dynamo_db = boto3.resource('dynamodb')
        raid_table = dynamo_db.Table(table_name)

        # Check if RAiD exists
        query_response = raid_table.query(KeyConditionExpression=Key('handle').eq(raid_handle))

        if query_response["Count"] != 1:
            return web_helpers.generate_web_body_response('404', {'message': "RAiD handle not found"}, event)

        # Assign raid item to single item, since the result will be an array of one item
        raid_item = query_response['Items'][0]

        return {
            'statusCode': '307',
            "headers": {
                "Access-Control-Allow-Headers": "Content-Type,Authorization,X-Amz-Date,X-Api-Key,X-Amz-Security-Token",
                "Access-Control-Allow-Methods": "DELETE,GET,HEAD,OPTIONS,PATCH,POST,PUT",
                "Access-Control-Allow-Origin": "*",
                'location': raid_item['contentPath']
            }
        }

    except:
        logger.error('Unable to get RAiD: {}'.format(sys.exc_info()[0]))
        return web_helpers.generate_web_body_response(
            '500',
            {'message': "Unable to fetch RAiD due to an error. Please check structure of the parameters."},
            event
        )
