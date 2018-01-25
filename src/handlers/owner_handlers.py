import sys
import logging
import boto3
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError
import json
import urllib
from helpers import web_helpers
from helpers import db
import settings

# Set Logging Level
logger = logging.getLogger()
logger.setLevel(logging.ERROR)


def get_owner_raids_handler(event, context):
    """
    Return RAiDs associated to the authenticated owner with optional parameters for filter and search options
    :param event:
    :param context:
    :return:
    """
    provider = event['requestContext']['authorizer']['provider']

    query_parameters = {
        'IndexName': 'NameRoleIndex',
        'ProjectionExpression': "raidName, handle, startDate, endDate",
        'FilterExpression': Attr('endDate').not_exists(),
        'KeyConditionExpression': Key('name-role').eq("{}-{}".format(provider, 'owner'))
    }

    return web_helpers.generate_table_list_response(
        event, query_parameters,
        settings.get_environment_table(
            settings.ASSOCIATION_TABLE,
            event['requestContext']['authorizer']['environment']
        )
    )


def update_raid_owner_handler(event, context):
    """
    Change the ownership of a RAiD to another provider
    :param event:
    :param context:
    :return:
    """
    try:
        raid_handle = urllib.unquote(urllib.unquote(event["pathParameters"]["raidId"]))
        body = json.loads(event["body"])
        new_owner = body['name']
    except ValueError as e:
        logger.error('Unable to capture RAiD or content path: {}'.format(e))
        return web_helpers.generate_web_body_response(
            '400',
            {'message': "Your request body must be valid JSON with a valid path parameter RAiD handle "
                        "URL encoded string."},
            event
        )
    except KeyError as e:
        logger.error('Unable to capture RAiD or content path: {}'.format(e))
        return web_helpers.generate_web_body_response('400', {
            'message': "An 'owner' must be provided in the body of the request."}, event)

    try:
        # Get current environment
        environment = event['requestContext']['authorizer']['environment']

        # Initialise DynamoDB Tables
        dynamo_db = boto3.resource('dynamodb')
        raid_table = dynamo_db.Table(
            settings.get_environment_table(
                settings.RAID_TABLE,
                environment
            )
        )

        association_index_table = dynamo_db.Table(
            settings.get_environment_table(
                settings.ASSOCIATION_TABLE, environment
            )
        )

        # Check if RAiD exists
        query_response = raid_table.query(KeyConditionExpression=Key('handle').eq(raid_handle))

        if query_response["Count"] != 1:
            return web_helpers.generate_web_body_response(
                '400', {'message': "Invalid RAiD handle provided in parameter path. Ensure it is a valid RAiD handle"
                                   " URL encoded string"},
                event
            )

        # Assign raid item to single item, since the result will be an array of one item
        raid_item = query_response['Items'][0]

        # Check Owner
        authorised_provider = event['requestContext']['authorizer']['provider']

        if raid_item["owner"] != authorised_provider:
            return web_helpers.generate_web_body_response(
                '403', {'message': "Only the current RAiD owner can modify ownership"}, event
            )

        # Change association of the current owner to a normal provider
        db.end_provider_ownership(association_index_table, raid_handle, raid_item["owner"], raid_item['meta']['name'])

        # Create new provider owner or promote existing one
        db.create_provider_ownership(association_index_table, raid_handle, new_owner, raid_item['meta']['name'])

        # Update the RAiD in the Database
        raid_table.update_item(
            Key={
                'handle': raid_handle
            },
            UpdateExpression="set #o = :o",
            ExpressionAttributeNames={
                '#o': 'owner'
            },
            ExpressionAttributeValues={
                ':o': new_owner
            }
        )

        return web_helpers.generate_web_body_response(
            '200',
            {
                'handle': raid_handle,
                'owner': new_owner,
            },
            event
        )

    except ClientError as e:
        logger.error('Unable to update RAiD owner: {}'.format(e))
        logger.error(str(e))
        return web_helpers.generate_web_body_response('500', {'message': "Unable to update RAiD owner."}, event)
    except Exception as e:
        logger.error('Unable to update RAiD owner: {}'.format(sys.exc_info()[0]))
        logger.error(str(e))
        return web_helpers.generate_web_body_response(
            '400',
            {'message': "Unable to perform request due to an error. Please check structure of the body."},
            event
        )
