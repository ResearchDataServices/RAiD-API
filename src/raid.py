from __future__ import print_function

import os
import sys
import logging
import base64
import datetime
import boto3
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError
import json
import urllib
import requests
from random import randint
from xml.etree import ElementTree

# Set Logging Level
logger = logging.getLogger()
logger.setLevel(logging.ERROR)


class AndsMintingError(Exception):
    """
    Exception used for an unsuccessful content path and handle minting
    """
    pass


def generate_web_body_response(status_code, body):
    """
    Generate a valid API Gateway CORS enabled JSON body response
    :param status_code: string of a HTTP status code
    :param body: Dictionary object, converted to JSON
    :return:
    """
    return {
        'statusCode': status_code,
        "headers": {
            "Access-Control-Allow-Headers": "Content-Type,Authorization,X-Amz-Date,X-Api-Key,X-Amz-Security-Token",
            "Access-Control-Allow-Methods": "DELETE,GET,HEAD,OPTIONS,PATCH,POST,PUT",
            "Access-Control-Allow-Origin": "*"
        },
        'body': json.dumps(body)
    }


def ands_handle_request(url_path, app_id, identifier, auth_domain):
    """
    Build a minting (create/update) query for ANDS and parse XML response
    :param url_path:
    :param app_id:
    :param identifier:
    :param auth_domain:
    :return:
    """
    xml_data = """
                <request name="mint">
                    <properties>
                        <property name="appId" value="{}"/>
                        <property name="identifier" value="{}"/>
                        <property name="authDomain" value="{}"/>
                    </properties>
                </request>
                """.format(app_id, identifier, auth_domain)
    headers = {'Content-Type': 'application/xml'}
    response = requests.post(url_path, data=xml_data, headers=headers)

    xml_tree = ElementTree.fromstring(response.content)

    # Get result of root XML tag response and read all child tags into a to dictionary
    if xml_tree.attrib["type"] == "success":
        response_data = {
            "handle": xml_tree.find("identifier").attrib["handle"],
            "contentIndex": xml_tree.find("identifier/property").attrib["index"],
            "timestamp": xml_tree.find("timestamp").text,
            "message": xml_tree.find("message").text
        }
        return response_data
    else:
        raise AndsMintingError("Unable to mint content path for an ANDS handle: {}".format(
            xml_tree.find("message").text))


def generate_random_handle():
    """
    Generate a random URL handle for testing
    :return:
    """
    hdl = 'http://hdl.handle.net/10.1000/' + str(randint(0,999))
    return hdl


def create_handler(event, context):
    """
    Create and new RAiD by; generating a handle, registering with ANDS and putting to the RAiD DB and Provider Index.
    :param event: 
    :param context:
    :return: RAiD object
    """
    try:
        # Initialise DynamoDB
        dynamo_db = boto3.resource('dynamodb')
        raid_table = dynamo_db.Table(os.environ["RAID_TABLE"])
        provider_index_table = dynamo_db.Table(os.environ["PROVIDER_TABLE"])

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
                raid_item['contentPath'] = generate_random_handle()

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
                    return generate_web_body_response(
                        '400', {'message': "Incorrect date format, should be yyyy-MM-dd hh:mm:ss"})
        else:
            raid_item['contentPath'] = generate_random_handle()

        # Mints ANDS handle
        ands_url_path = "{}mint?type=URL&value={}".format(os.environ["ANDS_SERVICE"], raid_item['contentPath'])
        ands_mint = ands_handle_request(ands_url_path, os.environ["ANDS_APP_ID"], "raid", "raid.org.au")

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

        return generate_web_body_response('200', {
            'raid': raid_item,
            'providers': [
                {
                    'provider': service_item['provider'],
                    'startDate': service_item['startDate'],
                    'endDate': ''
                }
            ]
        })
    except AndsMintingError as e:
        logger.error('Unable to mint content path for RAiD creation: {}'.format(e))
        return generate_web_body_response('500', {
            'message': "Unable to create a RAiD as ANDS was unable to mint the content path."})

    except:
        logger.error('Unable to create RAiD: {}'.format(sys.exc_info()[0]))
        return generate_web_body_response('400', {
            'message': "Unable to perform request due to error. Please check structure of the body."})


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
        return generate_web_body_response('400', {'message': "Your request body must be valid JSON."})
    except KeyError as e:
        logger.error('Unable to capture RAiD or content path: {}'.format(e))
        return generate_web_body_response('400', {
            'message': "A 'contentPath' URL string must be provided in the body of the request."})

    try:
        # Initialise DynamoDB
        dynamo_db = boto3.resource('dynamodb')
        raid_table = dynamo_db.Table(os.environ["RAID_TABLE"])

        # Check if RAiD exists
        query_response = raid_table.query(KeyConditionExpression=Key('handle').eq(raid_handle))

        if query_response["Count"] != 1:
            return generate_web_body_response('400', {
                'message': "Invalid RAiD handle provided in parameter path. "
                           "Ensure it is a valid RAiD handle URL encoded string"})

        # Assign raid item to single item, since the result will be an array of one item
        raid_item = query_response['Items'][0]

        # Assign default value if none exists
        if "contentIndex" not in raid_item:
            raid_item["contentIndex"] = "1"

        # Mints ANDS handle
        ands_url_path = "{}modifyValueByIndex?handle={}&value={}index={}".format(os.environ["ANDS_SERVICE"],
                                                                                 raid_item['handle'],
                                                                                 new_content_path,
                                                                                 raid_item['contentIndex'])

        ands_mint = ands_handle_request(ands_url_path, os.environ["ANDS_APP_ID"], "raid", "raid.org.au")

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

        return generate_web_body_response('200', update_response["Attributes"])

    except ClientError as e:
        logger.error('Unable to update content path in DynamoDB: {}'.format(e))
        return generate_web_body_response('500', {'message': "Unable to update content path value."})

    except AndsMintingError as e:
        logger.error('Unable to update content path with ANDS: {}'.format(e))
        return generate_web_body_response('500', {
            'message': "Unable to modify the RAiD as ANDS was unable to mint the content path."})

    except:
        logger.error('Unable to update RAiD: {}'.format(sys.exc_info()[0]))
        return generate_web_body_response('400', {'message': "Unable to perform request due to an error. "
                                                             "Please check structure of the body."})


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
        return generate_web_body_response('400', {'message': "Incorrect path parameter type formatting for RAiD handle."
                                                             " Ensure it is a valid RAiD handle URL encoded string"})
    try:
        # Initialise DynamoDB
        dynamo_db = boto3.resource('dynamodb')
        raid_table = dynamo_db.Table(os.environ["RAID_TABLE"])

        # Check if RAiD exists
        query_response = raid_table.query(KeyConditionExpression=Key('handle').eq(raid_handle))

        if query_response["Count"] != 1:
            return generate_web_body_response('400', {'message': "Invalid RAiD handle provided in parameter path."
                                                                 " Ensure it is a valid RAiD handle URL encoded string"})

        # Assign raid item to single item, since the result will be an array of one item
        raid_item = query_response['Items'][0]

        # Interpret and validate query string parameters
        if event["queryStringParameters"]:
            parameters = event["queryStringParameters"]

            # Load listed providers and insert into RAiD object if lazy load is off
            if "lazy_load" in parameters and (parameters["lazy_load"] == 'False' or parameters["lazy_load"] == 'false'):
                provider_index_table = dynamo_db.Table(os.environ["PROVIDER_TABLE"])

                provider_query_parameters = {
                    'IndexName': 'HandleProviderIndex',
                    'KeyConditionExpression': Key('handle').eq(raid_handle)
                }

                # Query table using parameters given and built to return a list of RAiDs the owner is attached too
                provider_query_response = provider_index_table.query(**provider_query_parameters)
                raid_item["providers"] = provider_query_response["Items"]

        return generate_web_body_response('200', raid_item)

    except:
        logger.error('Unable to get RAiD: {}'.format(sys.exc_info()[0]))
        return generate_web_body_response('500', {'message': "Unable to fetch RAiD due to error. "
                                                          "Please check structure of the parameters."})


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

    return generate_table_list_response(event, query_parameters, os.environ["RAID_TABLE"])


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
        return generate_web_body_response('400', {'message': "Your request body must be valid JSON with a valid path"
                                                             " parameter RAiD handle URL encoded string."})
    except KeyError as e:
        logger.error('Unable to capture RAiD or content path: {}'.format(e))
        return generate_web_body_response('400', {
            'message': "An 'owner' must be provided in the body of the request."})

    try:
        # Initialise DynamoDB
        dynamo_db = boto3.resource('dynamodb')
        raid_table = dynamo_db.Table(os.environ["RAID_TABLE"])

        # Check if RAiD exists
        query_response = raid_table.query(KeyConditionExpression=Key('handle').eq(raid_handle))

        if query_response["Count"] != 1:
            return generate_web_body_response('400', {'message': "Invalid RAiD handle provided in parameter path. "
                                                                 "Ensure it is a valid RAiD handle URL encoded string"})

        # Assign raid item to single item, since the result will be an array of one item
        raid_item = query_response['Items'][0]

        # Check Owner
        authorised_provider = event['requestContext']['authorizer']['provider']

        if raid_item["owner"] != authorised_provider:
            return generate_web_body_response('403', {'message': "Only the current RAiD owner can modify ownership"})

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

        return generate_web_body_response('200', update_response["Attributes"])

    except ClientError as e:
        logger.error('Unable to update RAiD owner: {}'.format(e))
        return generate_web_body_response('500', {'message': "Unable to update RAiD owner."})
    except:
        logger.error('Unable to update RAiD owner: {}'.format(sys.exc_info()[0]))
        return generate_web_body_response('400', {'message': "Unable to perform request due to an error. "
                                                             "Please check structure of the body."})


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

    return generate_table_list_response(event, query_parameters, os.environ["PROVIDER_TABLE"])


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
        return generate_web_body_response('400', {
            'message': "Incorrect path parameter type formatting for RAiD handle. Ensure it is a URL encoded string"})

    query_parameters = {
        'IndexName': 'HandleProviderIndex',
        'KeyConditionExpression': Key('handle').eq(raid_handle)
    }

    return generate_table_list_response(event, query_parameters, os.environ["PROVIDER_TABLE"])


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
        return generate_web_body_response('400', {
            'message': "Incorrect path parameter type formatting for RAiD handle. Ensure it is a URL encoded string"})

    try:
        # Initialise DynamoDB
        dynamo_db = boto3.resource('dynamodb')
        raid_table = dynamo_db.Table(os.environ["RAID_TABLE"])

        # Check if RAiD exists
        query_response = raid_table.query(KeyConditionExpression=Key('handle').eq(raid_handle))

        if query_response["Count"] != 1:
            return generate_web_body_response('400', {
                'message': "Invalid RAiD handle provided in parameter path. "
                           "Ensure it is a valid RAiD handle URL encoded string"})

        # Insert association to provider index table
        provider_index_table = dynamo_db.Table(os.environ["PROVIDER_TABLE"])

        # Interpret and validate request body
        body = json.loads(event["body"])

        if "startDate" in body:
            try:
                start_date = datetime.datetime.strptime(body["startDate"], "%Y-%m-%d %H:%M:%S")
            except ValueError as e:
                logger.error('Unable to capture date: {}'.format(e))
                return generate_web_body_response('400', {
                    'message': "Incorrect date format, should be yyyy-MM-dd hh:mm:ss"})

        else:
            # Get current datetime
            start_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if "provider" not in body:
            return generate_web_body_response('400', {
                'message': "'provider' must be provided in your request body to create an association"})

        # Define RAiD item
        service_item = {
            'provider': body['provider'],
            'handle': raid_handle,
            'startDate': start_date
        }

        # Send Dynamo DB put for new RAiD
        provider_index_table.put_item(Item=service_item)

        return generate_web_body_response('200', service_item)

    except:
        logger.error('Unable to associate a provider to a RAiD: {}'.format(sys.exc_info()[0]))
        return generate_web_body_response('500', {
            'message': "Unable to perform request due to error. Please check structure of the body."})


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
        return generate_web_body_response('400', {
            'message': "Incorrect path parameter type formatting for RAiD handle. Ensure it is a URL encoded string"})

    try:
        # Initialise DynamoDB
        dynamo_db = boto3.resource('dynamodb')
        raid_table = dynamo_db.Table(os.environ["RAID_TABLE"])

        # Check if RAiD exists
        query_response = raid_table.query(KeyConditionExpression=Key('handle').eq(raid_handle))

        if query_response["Count"] != 1:
            return generate_web_body_response('400', {
                'message': "Invalid RAiD handle provided in parameter path. "
                           "Ensure it is a valid RAiD handle URL encoded string"})

        # Insert association to provider index table
        provider_index_table = dynamo_db.Table(os.environ["PROVIDER_TABLE"])

        # Interpret and validate request body
        body = json.loads(event["body"])

        if "endDate" in body:
            try:
                end_date = datetime.datetime.strptime(body["endDate"], "%Y-%m-%d %H:%M:%S")
            except ValueError as e:
                logger.error('Unable to capture date: {}'.format(e))
                return generate_web_body_response('400', {
                    'message': "Incorrect date format, should be yyyy-MM-dd hh:mm:ss"})
        else:
            # Get current datetime
            end_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if "provider" not in body:
            return generate_web_body_response('400', {
                'message': "'provider' must be provided in your request body to end an association"})

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

        return generate_web_body_response('200', update_response["Attributes"])
    except:
        logger.error('Unable to end a provider to a RAiD association: {}'.format(sys.exc_info()[0]))
        return generate_web_body_response('500', {
            'message': "Unable to perform request due to error. Please check structure of the body."})


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

    return generate_table_list_response(event, query_parameters, os.environ["INSTITUTION_TABLE"])


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
        return generate_web_body_response('400', {
            'message': "Incorrect path parameter type formatting for RAiD handle. Ensure it is a URL encoded string"})

    query_parameters = {
        'IndexName': 'HandleProviderIndex',
        'KeyConditionExpression': Key('handle').eq(raid_handle)
    }

    return generate_table_list_response(event, query_parameters, os.environ["INSTITUTION_TABLE"])


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
        return generate_web_body_response('400', {
            'message': "Incorrect path parameter type formatting for RAiD handle. Ensure it is a URL encoded string"})

    try:
        # Initialise DynamoDB
        dynamo_db = boto3.resource('dynamodb')
        raid_table = dynamo_db.Table(os.environ["RAID_TABLE"])

        # Check if RAiD exists
        query_response = raid_table.query(KeyConditionExpression=Key('handle').eq(raid_handle))

        if query_response["Count"] != 1:
            return generate_web_body_response('400', {
                'message': "Invalid RAiD handle provided in parameter path. "
                           "Ensure it is a valid RAiD handle URL encoded string"})

        # Insert association to institution index table
        institution_index_table = dynamo_db.Table(os.environ["INSTITUTION_TABLE"])

        # Interpret and validate request body
        body = json.loads(event["body"])

        if "startDate" in body:
            try:
                start_date = datetime.datetime.strptime(body["startDate"], "%Y-%m-%d %H:%M:%S")
            except ValueError as e:
                logger.error('Unable to capture date: {}'.format(e))
                return generate_web_body_response('400', {
                    'message': "Incorrect date format, should be yyyy-MM-dd hh:mm:ss"})

        else:
            # Get current datetime
            start_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if "grid" not in body:
            return generate_web_body_response('400', {
                'message': "'grid' must be provided in your request body to create an association"})

        # Define RAiD item
        institution_item = {
            'grid': body['grid'],
            'handle': raid_handle,
            'startDate': start_date
        }

        # Send Dynamo DB put for new RAiD
        institution_index_table.put_item(Item=institution_item)

        return generate_web_body_response('200', institution_item)

    except:
        logger.error('Unable to create an institution to a RAiD association: {}'.format(sys.exc_info()[0]))
        return generate_web_body_response('500', {
            'message': "Unable to perform request due to error. Please check structure of the body."})


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
        return generate_web_body_response('400', {
            'message': "Incorrect path parameter type formatting for RAiD handle. Ensure it is a URL encoded string"})

    try:
        # Initialise DynamoDB
        dynamo_db = boto3.resource('dynamodb')
        raid_table = dynamo_db.Table(os.environ["RAID_TABLE"])

        # Check if RAiD exists
        query_response = raid_table.query(KeyConditionExpression=Key('handle').eq(raid_handle))

        if query_response["Count"] != 1:
            return generate_web_body_response('400', {
                'message': "Invalid RAiD handle provided in parameter path. "
                           "Ensure it is a valid RAiD handle URL encoded string"})

        # Insert association to institution index table
        institution_index_table = dynamo_db.Table(os.environ["INSTITUTION_TABLE"])

        # Interpret and validate request body
        body = json.loads(event["body"])

        if "endDate" in body:
            try:
                end_date = datetime.datetime.strptime(body["endDate"], "%Y-%m-%d %H:%M:%S")
            except ValueError as e:
                logger.error('Unable to capture date: {}'.format(e))
                return generate_web_body_response('400', {
                    'message': "Incorrect date format, should be yyyy-MM-dd hh:mm:ss"})
        else:
            # Get current datetime
            end_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if "grid" not in body:
            return generate_web_body_response('400', {
                'message': "'grid' must be provided in your request body to end an association"})

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

        return generate_web_body_response('200', update_response["Attributes"])
    except:
        logger.error('Unable to end a institution to a RAiD association: {}'.format(sys.exc_info()[0]))
        return generate_web_body_response('500', {
            'message': "Unable to perform request due to error. Please check structure of the body."})


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
                return generate_web_body_response('400', {'message': "Incorrect parameter type formatting."})

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

        return generate_web_body_response('200', return_body)

    except:
        logger.error('Unable to generate a DynamoDB list response: {}'.format(sys.exc_info()[0]))
        return generate_web_body_response('500', {'message': "Unable to perform request due to error. "
                                                             "Please check structure of the parameters."})
