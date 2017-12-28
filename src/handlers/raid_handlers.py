import os
import sys
import logging
import datetime
import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
import json
import urllib
from helpers import web_helpers
from helpers import ands_helpers
from helpers import raid_helpers
import settings

# Set Logging Level
logger = logging.getLogger()
logger.setLevel(logging.ERROR)


def get_raids_handler(event, context):
    """
    Return RAiDs associated to the provier or institution with optional parameters for filter and search options
    :param event:
    :param context:
    :return:
    """
    # Get authenticated user type
    user_role = event['requestContext']['authorizer']['role']

    if user_role == 'service':
        provider = event['requestContext']['authorizer']['provider']
        query_parameters = {
            'IndexName': 'StartDateIndex',
            'KeyConditionExpression': Key('provider').eq(provider)
        }

        # Replace names dictionary
        replacement_dictionary = {'provider': 'entityId'}

        return web_helpers.generate_table_list_response(
            event, query_parameters,
            settings.get_environment_table(
                settings.PROVIDER_TABLE,
                event['requestContext']['authorizer']['environment']
            ),
            replacement_dictionary
        )

    elif user_role == 'institution':
        institution_grid = event['requestContext']['authorizer']['grid']
        query_parameters = {
            'IndexName': 'StartDateIndex',
            'KeyConditionExpression': Key('grid').eq(institution_grid)
        }

        # Replace names dictionary
        replacement_dictionary = {'grid': 'entityId'}

        return web_helpers.generate_table_list_response(
            event, query_parameters,
            settings.get_environment_table(
                settings.INSTITUTION_TABLE,
                event['requestContext']['authorizer']['environment']
            ),
            replacement_dictionary)

    return web_helpers.generate_web_body_response(
        '400',
        {'message': 'Unable to get RAiDs due to unknown user type: "{}".'.format(user_role)}
    )


def create_raid_handler(event, context):
    """
    Create and new RAiD by; generating a handle, registering with ANDS and putting to the RAiD DB and Provider Index.
    :param event:
    :param context:
    :return: RAiD object
    """
    try:
        environment = event['requestContext']['authorizer']['environment']

        # Initialise DynamoDB
        dynamo_db = boto3.resource('dynamodb')
        raid_table = dynamo_db.Table(settings.get_environment_table(settings.RAID_TABLE, environment))
        provider_index_table = dynamo_db.Table(settings.get_environment_table(settings.PROVIDER_TABLE, environment))

        # Get current datetime
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Define Initial RAiD item
        raid_item = {
            'creationDate': now,
            'owner': event['requestContext']['authorizer']['provider']
        }

        # Interpret and validate request body
        if event["body"]:
            body = json.loads(event["body"])
            # Check for provided content path to mint
            if "contentPath" in body:
                raid_item['contentPath'] = body["contentPath"]
            else:
                raid_item['contentPath'] = settings.RAID_SITE_URL

            if "meta" in body:
                raid_item['meta'] = body['meta']

            else:
                raid_item['meta'] = {}

            # Auto-generate RAiD descriptive fields if they do not exist
            if 'name' not in raid_item['meta']:
                raid_item['meta'] = {'name': raid_helpers.generate_random_name()}

            if 'description' not in raid_item['meta']:
                raid_item['meta']['description'] = "RAiD created by '{}' at '{}'".format(
                    event['requestContext']['authorizer']['provider'], now)

            if "startDate" in body:
                try:
                    start_date = body["startDate"]
                    datetime.datetime.strptime(start_date, "%Y-%m-%d %H:%M:%S")
                    raid_item['startDate'] = start_date
                except ValueError as e:
                    logger.error('Unable to capture date: {}'.format(e))
                    return web_helpers.generate_web_body_response(
                        '400',
                        {'message': "Incorrect date format, should be yyyy-MM-dd hh:mm:ss"},
                        event
                    )
        else:
            raid_item['contentPath'] = settings.RAID_SITE_URL

        # Mints ANDS handle
        if environment == settings.DEMO_ENVIRONMENT:
            ands_url_path = "{}mint?type=URL&value={}".format(os.environ["DEMO_ANDS_SERVICE"], raid_item['contentPath'])
        elif environment == settings.LIVE_ENVIRONMENT:
            ands_url_path = "{}mint?type=URL&value={}".format(os.environ["ANDS_SERVICE"], raid_item['contentPath'])

        ands_mint = ands_helpers.ands_handle_request(ands_url_path, os.environ["ANDS_APP_ID"], "raid", "raid.org.au")

        ands_handle = ands_mint["handle"]

        # Insert minted handle into raid item
        raid_item['handle'] = ands_handle
        raid_item['contentIndex'] = ands_mint["contentIndex"]

        # Send Dynamo DB put for new RAiD
        raid_table.put_item(Item=raid_item)

        # Define provider association item
        service_item = {
            'provider': event['requestContext']['authorizer']['provider'],
            'handle': ands_handle,
            'startDate': now,
            'name': raid_item['meta']['name']
            # TODO Association Type for Owner
        }

        # Send Dynamo DB put for new association
        provider_index_table.put_item(Item=service_item)

        return web_helpers.generate_web_body_response(
            '200',
            {
                'raid': raid_item,
                'providers': [
                    {
                        'provider': service_item['provider'],
                        'startDate': service_item['startDate'],
                        'endDate': ''
                    }
                ]
            },
            event
        )
    except ands_helpers.AndsMintingError as e:
        logger.error('Unable to mint content path for RAiD creation: {}'.format(e))
        return web_helpers.generate_web_body_response('500', {
            'message': "Unable to create a RAiD as ANDS was unable to mint the content path."}, event)

    except:
        logger.error('Unable to create RAiD: {}'.format(sys.exc_info()[0]))
        return web_helpers.generate_web_body_response('400', {
            'message': "Unable to perform request due to error. Please check structure of the body."}, event)


def get_raid_handler(event, context):
    """

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
            {'message': "Incorrect path parameter type formatting for RAiD handle. Ensure it is a valid RAiD handle URL"
                        " encoded string"},
            event
        )
    try:
        # Initialise DynamoDB
        dynamo_db = boto3.resource('dynamodb')
        raid_table = dynamo_db.Table(
            settings.get_environment_table(settings.RAID_TABLE, event['requestContext']['authorizer']['environment']))

        # Check if RAiD exists
        query_response = raid_table.query(KeyConditionExpression=Key('handle').eq(raid_handle))

        if query_response["Count"] != 1:
            return web_helpers.generate_web_body_response(
                '400',
                {'message': "Invalid RAiD handle provided in parameter path. Ensure it is a valid RAiD handle URL"
                            " encoded string"},
                event
            )

        # Assign raid item to single item, since the result will be an array of one item
        raid_item = query_response['Items'][0]

        # Interpret and validate query string parameters
        if event["queryStringParameters"]:
            parameters = event["queryStringParameters"]

            # Load listed providers and insert into RAiD object if lazy load is off
            if "lazy_load" in parameters and (parameters["lazy_load"] == 'False' or parameters["lazy_load"] == 'false'):
                # Get Provider list
                provider_index_table = dynamo_db.Table(
                    settings.get_environment_table(
                        settings.PROVIDER_TABLE, event['requestContext']['authorizer']['environment']
                    )
                )

                provider_query_parameters = {
                    'IndexName': 'HandleProviderIndex',
                    'KeyConditionExpression': Key('handle').eq(raid_handle)
                }

                # Query table using parameters given and built to return a list of RAiDs the owner is attached too
                provider_query_response = provider_index_table.query(**provider_query_parameters)

                providers = provider_query_response["Items"]

                """
                # Get metadata for each listed metadata
                for provider in providers:
                    provider_metadata_table = dynamo_db.Table(os.environ["PROVIDER_METADATA_TABLE"])
                    provider_metadata_query_response = provider_metadata_table.query(
                        KeyConditionExpression=Key('name').eq(provider['provider']))
                    if provider_metadata_query_response["Count"] > 0:
                        provider['metadata'] = provider_metadata_query_response['Items'][0]
                """

                raid_item["providers"] = providers

                # Get institution list
                institution_index_table = dynamo_db.Table(
                    settings.get_environment_table(
                        settings.INSTITUTION_TABLE,
                        event['requestContext']['authorizer']['environment']
                    )
                )

                query_parameters = {
                    'IndexName': 'HandleGridIndex',
                    'KeyConditionExpression': Key('handle').eq(raid_handle)
                }

                # Query table using parameters given and built to return a list of RAiDs the owner is attached too
                institution_query_response = institution_index_table.query(**query_parameters)
                raid_item["institutions"] = institution_query_response["Items"]

        return web_helpers.generate_web_body_response('200', raid_item, event)

    except:
        logger.error('Unable to get RAiD: {}'.format(sys.exc_info()[0]))
        return web_helpers.generate_web_body_response(
            '500',
            {'message': "Unable to fetch RAiD due to error. Please check structure of the parameters."},
            event
        )


def update_raid(event, context):
    """
    Update the description and content path of a RAiD and mint the new path with the ANDS Service
    :param event:
    :param context:
    :return: RAiD object
    """
    # Check for provided RAiD and content path to mint
    try:
        raid_handle = urllib.unquote(urllib.unquote(event["pathParameters"]["raidId"]))
        body = json.loads(event["body"])
        new_content_path = body['contentPath']
        new_description = body['description']
        name = body['name']
    except ValueError as e:
        logger.error('Unable to capture RAiD or content path: {}'.format(e))
        return web_helpers.generate_web_body_response(
            '400',
            {'message': "Your request body must be valid JSON."},
            event
        )
    except KeyError as e:
        logger.error('Unable to capture description or content path: {}'.format(e))
        return web_helpers.generate_web_body_response(
            '400',
            {'message': "A 'name' 'description' and 'contentPath' URL string must be provided in the body of the "
                        "request."},
            event
        )

    try:
        environment = event['requestContext']['authorizer']['environment']

        # Initialise DynamoDB
        dynamo_db = boto3.resource('dynamodb')
        raid_table = dynamo_db.Table(settings.get_environment_table(settings.RAID_TABLE, environment))

        # Check if RAiD exists
        query_response = raid_table.query(KeyConditionExpression=Key('handle').eq(raid_handle))

        if query_response["Count"] != 1:
            return web_helpers.generate_web_body_response('400', {
                'message': "Invalid RAiD handle provided in parameter path. "
                           "Ensure it is a valid RAiD handle URL encoded string"}, event)

        # Assign raid item to single item, since the result will be an array of one item
        raid_item = query_response['Items'][0]

        # Assign default value if none exists
        if "contentIndex" not in raid_item:
            raid_item["contentIndex"] = "1"

        # # Mints ANDS handle  # TODO
        # if environment == settings.DEMO_ENVIRONMENT:
        #     ands_url_path = "{}modifyValueByIndex?handle={}&value={}index={}".format(os.environ["DEMO_ANDS_SERVICE"],
        #                                                                              raid_item['handle'],
        #                                                                              new_content_path,
        #                                                                              raid_item['contentIndex'])
        #
        # elif environment == settings.LIVE_ENVIRONMENT:
        #     ands_url_path = "{}modifyValueByIndex?handle={}&value={}index={}".format(os.environ["ANDS_SERVICE"],
        #                                                                              raid_item['handle'],
        #                                                                              new_content_path,
        #                                                                              raid_item['contentIndex'])
        #
        # ands_mint = ands_helpers.ands_handle_request(ands_url_path, os.environ["ANDS_APP_ID"], "raid", "raid.org.au")

        # Update content path and index
        update_response = raid_table.update_item(
            Key={
                'handle': raid_handle
            },
            UpdateExpression="set meta.#n = :n, meta.description = :d, contentPath = :c, contentIndex = :i",
            ExpressionAttributeNames={
                '#n': 'name'
            },
            ExpressionAttributeValues={
                ':n': name,
                ':d': new_description,
                ':c': new_content_path,
                # ':i': ands_mint["contentIndex"]  # TODO
                ':i': "1"
            },
            ReturnValues="ALL_NEW"
        )

        return web_helpers.generate_web_body_response('200', update_response["Attributes"], event)

    except ClientError as e:
        logger.error('Unable to update content path in DynamoDB: {}'.format(e))
        return web_helpers.generate_web_body_response('500', {'message': "Unable to update content path value."}, event)

    except ands_helpers.AndsMintingError as e:
        logger.error('Unable to update content path with ANDS: {}'.format(e))
        return web_helpers.generate_web_body_response('500', {
            'message': "Unable to modify the RAiD as ANDS was unable to mint the content path."}, event)

    except:
        logger.error('Unable to update RAiD: {}'.format(sys.exc_info()[0]))
        return web_helpers.generate_web_body_response('400', {'message': "Unable to perform request due to an error."
                                                                         " Please check structure of the body."}, event)

