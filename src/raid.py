import os
import sys
import logging
import base64
import datetime
import boto3
from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError
import json
import urllib
from helpers import web_helpers
from helpers import ands_helpers

# Constants
RAID_TABLE = "RAID_TABLE"
PROVIDER_TABLE = "PROVIDER_TABLE"
INSTITUTION_TABLE = "INSTITUTION_TABLE"
DEMO_ENVIRONMENT = "demo"
LIVE_ENVIRONMENT = "live"
RAID_SITE_URL = "https://www.raid.org.au/"

# Set Logging Level
logger = logging.getLogger()
logger.setLevel(logging.ERROR)


def get_environment_table(table_name, environment):
    """
    return the demo of live table name from environment variables
    :param table_name:
    :param environment:
    :return:
    """
    if table_name == RAID_TABLE:
        if environment == DEMO_ENVIRONMENT:
            return os.environ["RAID_DEMO_TABLE"]
        elif environment == LIVE_ENVIRONMENT:
            return os.environ["RAID_TABLE"]
    elif table_name == PROVIDER_TABLE:
        if environment == DEMO_ENVIRONMENT:
            return os.environ["PROVIDER_DEMO_TABLE"]
        elif environment == LIVE_ENVIRONMENT:
            return os.environ["PROVIDER_TABLE"]
    elif table_name == INSTITUTION_TABLE:
        if environment == DEMO_ENVIRONMENT:
            return os.environ["INSTITUTION_DEMO_TABLE"]
        elif environment == LIVE_ENVIRONMENT:
            return os.environ["INSTITUTION_TABLE"]


def authenticate_token_handler(event, context):
    """

    :param event:
    :param context:
    :return:
    """
    pass


def create_handler(event, context):
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
        raid_table = dynamo_db.Table(get_environment_table(RAID_TABLE, environment))
        provider_index_table = dynamo_db.Table(get_environment_table(PROVIDER_TABLE, environment))

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
                raid_item['contentPath'] = RAID_SITE_URL

            if "description" in body:
                raid_item['description'] = body["description"]

            if "meta" in body:
                raid_item['meta'] = body["meta"]

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
            raid_item['contentPath'] = RAID_SITE_URL

        # Mints ANDS handle
        if environment == DEMO_ENVIRONMENT:
            ands_url_path = "{}mint?type=URL&value={}".format(os.environ["DEMO_ANDS_SERVICE"], raid_item['contentPath'])
        elif environment == LIVE_ENVIRONMENT:
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
            'startDate': now
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


def update_content_path_handler(event, context):
    """
    Update the content path of a RAiD and mint the new path with the ANDS Service
    :param event:
    :param context:
    :return: RAiD object
    """
    # Check for provided RAiD and content path to mint
    try:
        raid_handle = urllib.unquote(urllib.unquote(event["pathParameters"]["raidId"]))
        body = json.loads(event["body"])
        new_content_path = body['contentPath']
    except ValueError as e:
        logger.error('Unable to capture RAiD or content path: {}'.format(e))
        return web_helpers.generate_web_body_response('400', {'message': "Your request body must be valid JSON."}, event)
    except KeyError as e:
        logger.error('Unable to capture RAiD or content path: {}'.format(e))
        return web_helpers.generate_web_body_response('400', {
            'message': "A 'contentPath' URL string must be provided in the body of the request."}, event)

    try:
        environment = event['requestContext']['authorizer']['environment']

        # Initialise DynamoDB
        dynamo_db = boto3.resource('dynamodb')
        raid_table = dynamo_db.Table(get_environment_table(RAID_TABLE, environment))

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

        # Mints ANDS handle
        if environment == DEMO_ENVIRONMENT:
            ands_url_path = "{}modifyValueByIndex?handle={}&value={}index={}".format(os.environ["DEMO_ANDS_SERVICE"],
                                                                                     raid_item['handle'],
                                                                                     new_content_path,
                                                                                     raid_item['contentIndex'])

        elif environment == LIVE_ENVIRONMENT:
            ands_url_path = "{}modifyValueByIndex?handle={}&value={}index={}".format(os.environ["ANDS_SERVICE"],
                                                                                     raid_item['handle'],
                                                                                     new_content_path,
                                                                                     raid_item['contentIndex'])

        ands_mint = ands_helpers.ands_handle_request(ands_url_path, os.environ["ANDS_APP_ID"], "raid", "raid.org.au")

        # Update content path and index
        update_response = raid_table.update_item(
            Key={
                'handle': raid_handle
            },
            UpdateExpression="set contentPath = :c, contentIndex = :c",
            ExpressionAttributeValues={
                ':c': new_content_path,
                ':i': ands_mint["contentIndex"]
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
        return web_helpers.generate_web_body_response('400', {'message': "Unable to perform request due to an error. "
                                                             "Please check structure of the body."}, event)


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
        return web_helpers.generate_web_body_response('400', {'message': "Incorrect path parameter type formatting for RAiD handle."
                                                             " Ensure it is a valid RAiD handle URL encoded string"}, event)
    try:
        # Initialise DynamoDB
        dynamo_db = boto3.resource('dynamodb')
        raid_table = dynamo_db.Table(
            get_environment_table(RAID_TABLE, event['requestContext']['authorizer']['environment']))

        # Check if RAiD exists
        query_response = raid_table.query(KeyConditionExpression=Key('handle').eq(raid_handle))

        if query_response["Count"] != 1:
            return web_helpers.generate_web_body_response('400', {'message': "Invalid RAiD handle provided in parameter path."
                                                                 " Ensure it is a valid RAiD handle URL encoded string"}, event)

        # Assign raid item to single item, since the result will be an array of one item
        raid_item = query_response['Items'][0]

        # Interpret and validate query string parameters
        if event["queryStringParameters"]:
            parameters = event["queryStringParameters"]

            # Load listed providers and insert into RAiD object if lazy load is off
            if "lazy_load" in parameters and (parameters["lazy_load"] == 'False' or parameters["lazy_load"] == 'false'):
                # Get Provider list
                provider_index_table = dynamo_db.Table(
                    get_environment_table(PROVIDER_TABLE, event['requestContext']['authorizer']['environment']))

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
                    get_environment_table(INSTITUTION_TABLE, event['requestContext']['authorizer']['environment']))

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
        return web_helpers.generate_web_body_response('500', {'message': "Unable to fetch RAiD due to error. "
                                                          "Please check structure of the parameters."}, event)


def get_owner_raids_handler(event, context):
    """
    Return RAiDs associated to the authenticated owner with optional parameters for filter and search options
    :param event:
    :param context:
    :return:
    """
    query_parameters = {
        'IndexName': 'OwnerIndex',
        'KeyConditionExpression': Key('owner').eq(event['requestContext']['authorizer']['provider'])
    }

    return generate_table_list_response(
        event, query_parameters,
        get_environment_table(RAID_TABLE, event['requestContext']['authorizer']['environment']))


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
        new_owner = body['provider']
    except ValueError as e:
        logger.error('Unable to capture RAiD or content path: {}'.format(e))
        return web_helpers.generate_web_body_response('400', {'message': "Your request body must be valid JSON with a valid path"
                                                             " parameter RAiD handle URL encoded string."}, event)
    except KeyError as e:
        logger.error('Unable to capture RAiD or content path: {}'.format(e))
        return web_helpers.generate_web_body_response('400', {
            'message': "An 'owner' must be provided in the body of the request."}, event)

    try:
        # Initialise DynamoDB
        dynamo_db = boto3.resource('dynamodb')
        raid_table = dynamo_db.Table(
            get_environment_table(RAID_TABLE, event['requestContext']['authorizer']['environment']))

        # Check if RAiD exists
        query_response = raid_table.query(KeyConditionExpression=Key('handle').eq(raid_handle))

        if query_response["Count"] != 1:
            return web_helpers.generate_web_body_response('400', {'message': "Invalid RAiD handle provided in parameter path. "
                                                                 "Ensure it is a valid RAiD handle URL encoded string"}, event)

        # Assign raid item to single item, since the result will be an array of one item
        raid_item = query_response['Items'][0]

        # Check Owner
        authorised_provider = event['requestContext']['authorizer']['provider']

        if raid_item["owner"] != authorised_provider:
            return web_helpers.generate_web_body_response('403', {'message': "Only the current RAiD owner can modify ownership"}, event)

        # Check if new owner exists # TODO

        # Update the RAiD in the Database
        update_response = raid_table.update_item(
            Key={
                'handle': raid_handle
            },
            UpdateExpression="set owner = :o",
            ExpressionAttributeValues={
                ':o': new_owner
            },
            ReturnValues="ALL_NEW"
        )

        return web_helpers.generate_web_body_response('200', update_response["Attributes"], event)

    except ClientError as e:
        logger.error('Unable to update RAiD owner: {}'.format(e))
        return web_helpers.generate_web_body_response('500', {'message': "Unable to update RAiD owner."}, event)
    except:
        logger.error('Unable to update RAiD owner: {}'.format(sys.exc_info()[0]))
        return web_helpers.generate_web_body_response('400', {'message': "Unable to perform request due to an error. "
                                                             "Please check structure of the body."}, event)


def get_provider_raids_handler(event, context):
    """
    Return RAiDs associated to the provider in the path with optional parameters for filter and search options
    :param event:
    :param context:
    :return:
    """
    query_parameters = {
        'IndexName': 'StartDateIndex',
        'KeyConditionExpression': Key('provider').eq(event["pathParameters"]["providerId"])
    }

    return generate_table_list_response(
        event, query_parameters,
        get_environment_table(PROVIDER_TABLE, event['requestContext']['authorizer']['environment']))


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
        return web_helpers.generate_web_body_response('400', {
            'message': "Incorrect path parameter type formatting for RAiD handle. Ensure it is a URL encoded string"}, event)

    query_parameters = {
        'IndexName': 'HandleProviderIndex',
        'KeyConditionExpression': Key('handle').eq(raid_handle)
    }

    return generate_table_list_response(
        event, query_parameters,
        get_environment_table(PROVIDER_TABLE, event['requestContext']['authorizer']['environment']))


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
        return web_helpers.generate_web_body_response('400', {
            'message': "Incorrect path parameter type formatting for RAiD handle. Ensure it is a URL encoded string"}, event)

    try:
        # Initialise DynamoDB
        dynamo_db = boto3.resource('dynamodb')
        raid_table = dynamo_db.Table(
            get_environment_table(RAID_TABLE, event['requestContext']['authorizer']['environment']))

        # Check if RAiD exists
        query_response = raid_table.query(KeyConditionExpression=Key('handle').eq(raid_handle))

        if query_response["Count"] != 1:
            return web_helpers.generate_web_body_response('400', {
                'message': "Invalid RAiD handle provided in parameter path. "
                           "Ensure it is a valid RAiD handle URL encoded string"}, event)

        # Insert association to provider index table
        provider_index_table = dynamo_db.Table(
            get_environment_table(PROVIDER_TABLE, event['requestContext']['authorizer']['environment']))

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
        return web_helpers.generate_web_body_response('400', {
            'message': "Incorrect path parameter type formatting for RAiD handle. Ensure it is a URL encoded string"}, event)

    try:
        # Initialise DynamoDB
        dynamo_db = boto3.resource('dynamodb')
        raid_table = dynamo_db.Table(
            get_environment_table(RAID_TABLE, event['requestContext']['authorizer']['environment']))

        # Check if RAiD exists
        query_response = raid_table.query(KeyConditionExpression=Key('handle').eq(raid_handle))

        if query_response["Count"] != 1:
            return web_helpers.generate_web_body_response('400', {
                'message': "Invalid RAiD handle provided in parameter path. "
                           "Ensure it is a valid RAiD handle URL encoded string"}, event)

        # Insert association to provider index table
        provider_index_table = dynamo_db.Table(
            get_environment_table(PROVIDER_TABLE, event['requestContext']['authorizer']['environment']))

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


def get_institution_raids_handler(event, context):
    """
    Return RAiDs associated to the institution in the path with optional parameters for filter and search options
    :param event:
    :param context:
    :return:
    """
    query_parameters = {
        'IndexName': 'StartDateIndex',
        'KeyConditionExpression': Key('grid').eq(event["pathParameters"]["grid"])
    }

    return generate_table_list_response(
        event, query_parameters,
        get_environment_table(INSTITUTION_TABLE, event['requestContext']['authorizer']['environment']))


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

    query_parameters = {
        'IndexName': 'HandleGridIndex',
        'KeyConditionExpression': Key('handle').eq(raid_handle)
    }

    return generate_table_list_response(
        event, query_parameters,
        get_environment_table(INSTITUTION_TABLE, event['requestContext']['authorizer']['environment']))


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
        # Initialise DynamoDB
        dynamo_db = boto3.resource('dynamodb')
        raid_table = dynamo_db.Table(
            get_environment_table(RAID_TABLE, event['requestContext']['authorizer']['environment']))

        # Check if RAiD exists
        query_response = raid_table.query(KeyConditionExpression=Key('handle').eq(raid_handle))

        if query_response["Count"] != 1:
            return web_helpers.generate_web_body_response('400', {
                'message': "Invalid RAiD handle provided in parameter path. "
                           "Ensure it is a valid RAiD handle URL encoded string"}, event)

        # Insert association to institution index table
        institution_index_table = dynamo_db.Table(
            get_environment_table(INSTITUTION_TABLE, event['requestContext']['authorizer']['environment']))

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

        if "grid" not in body:
            return web_helpers.generate_web_body_response('400', {
                'message': "'grid' must be provided in your request body to create an association"}, event)

        # Define RAiD item
        institution_item = {
            'grid': body['grid'],
            'handle': raid_handle,
            'startDate': start_date
        }

        # Send Dynamo DB put for new RAiD
        institution_index_table.put_item(Item=institution_item)

        return web_helpers.generate_web_body_response('200', institution_item, event)

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
        # Initialise DynamoDB
        dynamo_db = boto3.resource('dynamodb')
        raid_table = dynamo_db.Table(
            get_environment_table(RAID_TABLE, event['requestContext']['authorizer']['environment']))

        # Check if RAiD exists
        query_response = raid_table.query(KeyConditionExpression=Key('handle').eq(raid_handle))

        if query_response["Count"] != 1:
            return web_helpers.generate_web_body_response('400', {
                'message': "Invalid RAiD handle provided in parameter path. "
                           "Ensure it is a valid RAiD handle URL encoded string"}, event)

        # Insert association to institution index table
        institution_index_table = dynamo_db.Table(
            get_environment_table(INSTITUTION_TABLE, event['requestContext']['authorizer']['environment']))

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

        if "grid" not in body:
            return web_helpers.generate_web_body_response('400', {
                'message': "'grid' must be provided in your request body to end an association"}, event)

        # Update institution association
        update_response = institution_index_table.update_item(
            Key={
                'grid': body['grid'],
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
        logger.error('Unable to end a institution to a RAiD association: {}'.format(sys.exc_info()[0]))
        return web_helpers.generate_web_body_response('500', {
            'message': "Unable to perform request due to error. Please check structure of the body."}, event)


def generate_table_list_response(event, query_parameters, table):
    """
    A generic method for Dynamo DB queries that return a list of items.
    :param event: Dictionary of values provided from the invoking API Gateway
    :param query_parameters: Dictionary of DynamoDB parameters unique to the calling method
    :param table: String representing the name of the DynamoDB table
    :return:
    """
    try:
        # Initialise DynamoDB
        dynamo_db = boto3.resource('dynamodb')
        dynamo_db_table = dynamo_db.Table(table)

        # Interpret and validate request body for optional parameters
        if event["queryStringParameters"]:
            try:
                parameters = event["queryStringParameters"]
                if "limit" in parameters:
                    query_parameters["Limit"] = int(parameters["limit"])
                if "ascending" in parameters and \
                        (parameters["ascending"] == 'False' or parameters["ascending"] == 'false'):
                    query_parameters["ScanIndexForward"] = False
                if "exclusiveStartKey" in parameters:
                    query_parameters["ExclusiveStartKey"] = json.loads(base64.urlsafe_b64decode(
                        parameters["exclusiveStartKey"].encode("ascii")
                    ))
            except ValueError as e:
                logger.error('Incorrect parameter type formatting: {}'.format(e))
                return web_helpers.generate_web_body_response('400', {'message': "Incorrect parameter type formatting."}, event)

        # Query table using parameters given and built to return a list of RAiDs the owner is attached too
        query_response = dynamo_db_table.query(**query_parameters)

        # Build response body
        return_body = {
            'items': query_response["Items"],
            'count': query_response["Count"],
            'scannedCount': query_response["ScannedCount"]
        }

        if 'LastEvaluatedKey' in query_response:
            return_body['lastEvaluatedKey'] = base64.urlsafe_b64encode(json.dumps(query_response["LastEvaluatedKey"]))

        return web_helpers.generate_web_body_response('200', return_body, event)

    except:
        logger.error('Unable to generate a DynamoDB list response: {}'.format(sys.exc_info()[0]))
        return web_helpers.generate_web_body_response('500', {'message': "Unable to perform request due to error. "
                                                             "Please check structure of the parameters."}, event)


def get_raid_public_handler(event, context):
    """
    Show the existence of the RAiD and all public information metadata attached RAiDPublicModel
    :param event:
    :param context:
    :return:
    """
    try:
        raid_handle = urllib.unquote(urllib.unquote(event["pathParameters"]["raidId"]))

    except:
        logger.error('Unable to validate RAiD parameter: {}'.format(sys.exc_info()[0]))
        return web_helpers.generate_web_body_response('400', {'message': "Incorrect path parameter type formatting for RAiD handle."
                                                             " Ensure it is a valid RAiD handle URL encoded string"}, event)

    try:
        # Check if demo or live environment
        if event["queryStringParameters"]:
            try:
                parameters = event["queryStringParameters"]
                if "demo" in parameters and (parameters["demo"] == 'True' or parameters["demo"] == 'true'):
                    table_name = get_environment_table(RAID_TABLE, 'demo')
                else:
                    table_name = get_environment_table(RAID_TABLE, 'live')
            except ValueError as e:
                logger.error('Incorrect parameter type formatting: {}'.format(e))
                return web_helpers.generate_web_body_response('400', {'message': "Incorrect parameter type formatting."}, event)
        else:
            table_name = get_environment_table(RAID_TABLE, 'live')

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
        return web_helpers.generate_web_body_response('500', {'message': "Unable to fetch RAiD due to an error. "
                                                             "Please check structure of the parameters."}, event)


def redirect_raid_path_handler(event, context):
    """
    Redirect from a RAiD handle to it'c minted content path
    :param event:
    :param context:
    :return:
    """
    try:
        raid_handle = urllib.unquote(urllib.unquote(event["pathParameters"]["raidId"]))

    except:
        logger.error('Unable to validate RAiD parameter: {}'.format(sys.exc_info()[0]))
        return web_helpers.generate_web_body_response('400', {'message': "Incorrect path parameter type formatting for RAiD handle."
                                                             " Ensure it is a valid RAiD handle URL encoded string"}, event)

    try:
        # Check if demo or live environment
        if event["queryStringParameters"]:
            try:
                parameters = event["queryStringParameters"]
                if "demo" in parameters and (parameters["demo"] == 'True' or parameters["demo"] == 'true'):
                    table_name = get_environment_table(RAID_TABLE, 'demo')
                else:
                    table_name = get_environment_table(RAID_TABLE, 'live')
            except ValueError as e:
                logger.error('Incorrect parameter type formatting: {}'.format(e))
                return web_helpers.generate_web_body_response('400', {'message': "Incorrect parameter type formatting."}, event)
        else:
            table_name = get_environment_table(RAID_TABLE, 'live')

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
        return web_helpers.generate_web_body_response('500', {'message': "Unable to fetch RAiD due to an error. "
                                                             "Please check structure of the parameters."}, event)

