import os
import sys
import logging
import datetime
import boto3
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError
import json
import urllib.request, urllib.parse, urllib.error
from aws_xray_sdk.core import patch
from helpers import web_helpers
from helpers import ands_helpers
from helpers import raid_helpers
import settings

# Set Logging Level
logger = logging.getLogger()
logger.setLevel(logging.ERROR)

# AWS X-Ray Config
libs_to_patch = ('boto3', 'requests')
patch(libs_to_patch)


def get_raids_handler(event, context):
    """
    Return RAiDs associated to the provider or institution with optional parameters for filter and search options
    :param event:
    :param context:
    :return:
    """
    logger.error(json.dumps(event))
    provider = event['requestContext']['authorizer']['provider']

    query_parameters = {
        'IndexName': 'NameIndex',
        'ProjectionExpression': "raidName, handle, startDate, endDate, #r",
        'ExpressionAttributeNames': {"#r": "role"},
        'FilterExpression': Attr('endDate').not_exists(),
        'KeyConditionExpression': Key('name').eq(provider)
    }

    try:
        if event["queryStringParameters"]["owner"] == 'False' or event["queryStringParameters"]["owner"] == 'false':
                query_parameters["FilterExpression"] = Attr('endDate').not_exists() \
                                                       and (Attr('role').not_exists() or Attr('role').ne('owner'))

    except (KeyError, TypeError):
        query_parameters["FilterExpression"] = Attr('endDate').not_exists() \
                                               and (Attr('role').not_exists() or Attr('role').ne('owner'))

    except ValueError as e:
        logger.error('Incorrect parameter type formatting: {}'.format(e))
        return web_helpers.generate_web_body_response('400', {'message': "Incorrect parameter type formatting."}, event)

    return web_helpers.generate_table_list_response(
        event, query_parameters,
        settings.get_environment_table(settings.ASSOCIATION_TABLE, event['requestContext']['authorizer']['environment'])
    )


def create_raid_handler(event, context):
    """
    Create and new RAiD by; generating a handle, registering with ANDS and putting to the RAiD DB and Provider Index.
    :param event:
    :param context:
    :return: RAiD object
    """
    if 'requestContext' not in event:
        return {"message": "Warming Lambda container"}

    try:
        environment = event['requestContext']['authorizer']['environment']

        owner = event['requestContext']['authorizer']['provider']

        # Initialise DynamoDB
        dynamo_db = boto3.resource('dynamodb')
        raid_table = dynamo_db.Table(settings.get_environment_table(settings.RAID_TABLE, environment))

        # Get current datetime
        now = raid_helpers.get_current_datetime()

        # Define Initial RAiD item
        raid_item = {
            'creationDate': now,
            'owner': owner
        }

        # Interpret and validate request body
        if 'body' in event and event["body"]:
            body = json.loads(event["body"])
            # Check for provided content path to mint
            if "contentPath" in body:
                content_path = body["contentPath"]
            else:
                content_path = settings.RAID_SITE_URL

            if "meta" in body:
                raid_item['meta'] = body['meta']

            else:
                raid_item['meta'] = {}

            # Auto-generate RAiD descriptive fields if they do not exist
            if 'name' not in raid_item['meta']:
                raid_item['meta'] = {'name': raid_helpers.generate_random_name()}

            if 'description' not in raid_item['meta']:
                raid_item['meta']['description'] = "RAiD created by '{}' at '{}'".format(owner, now)

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
                raid_item['startDate'] = now
        else:
            content_path = settings.RAID_SITE_URL
            raid_item['startDate'] = now

        # Set content path
        raid_item['contentPath'] = content_path

        # Get correct ANDS Shared Secret
        if environment == settings.DEMO_ENVIRONMENT:
            ands_secret = os.environ["ANDS_DEMO_SECRET"]
        elif environment == settings.LIVE_ENVIRONMENT:
            ands_secret = os.environ["ANDS_SECRET"]

        # Get ANDS handle and content index
        ands_handle, ands_content_index = ands_helpers.get_new_ands_handle(
            environment,
            os.environ["ANDS_HANDLES_QUEUE"],
            os.environ["DEMO_ANDS_HANDLES_QUEUE"],
            os.environ["ANDS_SERVICE"],
            os.environ["DEMO_ANDS_SERVICE"],
            content_path,
            os.environ["ANDS_APP_ID"],
            ands_secret
        )

        # Insert minted handle into raid item
        raid_item['handle'] = ands_handle
        raid_item['contentIndex'] = ands_content_index

        # Send Dynamo DB put for new RAiD
        raid_table.put_item(Item=raid_item)

        # Define provider association item  # TODO move to DynamoDB Stream
        service_item = {
            'handle': ands_handle,
            'startDate': raid_item['startDate'],
            'name': owner,
            'raidName': raid_item['meta']['name'],
            'role': 'owner',
            'type': settings.SERVICE_ROLE,
            'name-role': '{}-{}'.format(owner, 'owner'),
            'handle-name': '{}-{}'.format(ands_handle, owner),
            'handle-type': '{}-{}'.format(ands_handle, settings.SERVICE_ROLE)
        }

        # Send Dynamo DB put for new association
        association_index_table = dynamo_db.Table(
            settings.get_environment_table(
                settings.ASSOCIATION_TABLE, environment
            )
        )
        association_index_table.put_item(Item=service_item)  # TODO move to DynamoDB Stream

        raid_item['providers'] = [
                    {
                        'provider': service_item['name'],
                        'startDate': service_item['startDate']
                    }
                ]

        return web_helpers.generate_web_body_response('200', raid_item, event)

    except ands_helpers.AndsMintingError as e:
        logger.error('Unable to mint content path for RAiD creation: {}'.format(e))
        return web_helpers.generate_web_body_response('500', {
            'message': "Unable to create a RAiD as ANDS was unable to mint the content path."}, event)

    except Exception as e:
        logger.error('Unable to create RAiD: {}'.format(e))
        return web_helpers.generate_web_body_response('400', {
            'message': "Unable to perform request due to error. Please check structure of the body."}, event)


def get_raid_handler(event, context):
    """

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
            {'message': "Incorrect path parameter type formatting for RAiD handle. Ensure it is a valid RAiD handle URL"
                        " encoded string"},
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
                # Initialise RAiD association table object
                association_index_table = dynamo_db.Table(
                    settings.get_environment_table(settings.ASSOCIATION_TABLE, environment)
                )

                # Get Provider list

                provider_query_parameters = {
                    'IndexName': 'HandleTypeIndex',
                    'ProjectionExpression': "#n, startDate, endDate",
                    'ExpressionAttributeNames': {"#n": "name"},
                    'KeyConditionExpression': Key('handle-type').eq('{}-{}'.format(raid_handle, settings.SERVICE_ROLE))
                }

                provider_query_response = association_index_table.query(**provider_query_parameters)
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
                institution_query_parameters = {
                    'IndexName': 'HandleTypeIndex',
                    'ProjectionExpression': "#n, startDate, endDate",
                    'ExpressionAttributeNames': {"#n": "name"},
                    'KeyConditionExpression': Key('handle-type').eq('{}-{}'.format(
                        raid_handle, settings.INSTITUTION_ROLE))
                }

                institution_query_response = association_index_table.query(**institution_query_parameters)
                raid_item["institutions"] = institution_query_response["Items"]

        return web_helpers.generate_web_body_response('200', raid_item, event)

    except Exception as e:
        logger.error('Unable to get RAiD: {}'.format(sys.exc_info()[0]))
        logger.error(str(e))
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
    if 'requestContext' not in event:
        return {"message": "Warming Lambda container"}

    # Check for provided RAiD and content path to mint
    try:
        raid_handle = urllib.parse.unquote(urllib.parse.unquote(event["pathParameters"]["raidId"]))
        body = json.loads(event["body"])
        new_content_path = body['contentPath']
        new_description = body['description']
        new_name = body['name']
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

        # Update name, content path and index
        update_response = raid_table.update_item(
            Key={
                'handle': raid_handle
            },
            UpdateExpression="set meta.#n = :n, meta.description = :d, contentPath = :c",
            ExpressionAttributeNames={
                '#n': 'name'
            },
            ExpressionAttributeValues={
                ':n': new_name,
                ':c': new_content_path,
                ':d': new_description
            },
            ReturnValues="ALL_NEW"
        )

        # Update name on all associations
        if 'name' not in raid_item['meta'] or new_name != raid_item['meta']['name']:
            association_index_table = dynamo_db.Table(
                settings.get_environment_table(
                    settings.ASSOCIATION_TABLE, environment
                )
            )

            association_query_parameters = {
                'ProjectionExpression': "startDate",
                'KeyConditionExpression': Key('handle').eq(raid_handle)
            }

            # Query table using parameters given and built to return a list of RAiDs the owner is attached too
            query_response = association_index_table.query(**association_query_parameters)

            for item in query_response['Items']:
                association_index_table.update_item(
                    Key={
                        'handle': raid_handle,
                        'startDate': item['startDate']
                    },
                    UpdateExpression="set #n = :n",
                    ExpressionAttributeNames={
                        '#n': 'raidName'
                    },
                    ExpressionAttributeValues={
                        ':n': new_name
                    }
                )

            while 'LastEvaluatedKey' in query_response:
                association_query_parameters['ExclusiveStartKey'] = query_response['LastEvaluatedKey']
                query_response = association_index_table.query(**association_query_parameters)
                for item in query_response['Items']:
                    association_index_table.update_item(
                        Key={
                            'handle': raid_handle,
                            'startDate': item['startDate']
                        },
                        UpdateExpression="set #n = :n",
                        ExpressionAttributeNames={
                            '#n': 'raidName'
                        },
                        ExpressionAttributeValues={
                            ':n': new_name
                        }
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

