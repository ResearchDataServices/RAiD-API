from __future__ import print_function

import os
import datetime
import boto3
import json
import urllib
from boto3.dynamodb.conditions import Key, Attr
from random import randint


def generate_handle():
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

        # Generate handle
        handle = generate_handle()

        # Define Initial RAiD item
        raid_item = {
            'handle': handle,
            'creationDate': now,
            'owner': event['requestContext']['authorizer']['provider']
        }

        # Interpret and validate request body
        if event["body"]:
            body = json.loads(event["body"])
            if "meta" in body:
                raid_item['meta'] = body["meta"]

            if "startDate" in body:
                try:
                    start_date = body["startDate"]
                    datetime.datetime.strptime(start_date, "%Y-%m-%d %H:%M:%S")
                    raid_item['startDate'] = start_date
                except ValueError:
                    return {
                        'statusCode': '400',
                        'body': json.dumps({'message': "Incorrect date format, should be yyyy-MM-dd hh:mm:ss"})
                    }

        # Send Dynamo DB put for new RAiD
        raid_table.put_item(Item=raid_item)

        # Define RAiD item
        service_item = {
            'provider': event['requestContext']['authorizer']['provider'],
            'handle': handle,
            'startDate': now
        }

        # Send Dynamo DB put for new RAiD
        provider_index_table.put_item(Item=service_item)

        return {
            'statusCode': '200',
            'body': json.dumps(
                {
                    'raid': raid_item,
                    'providers': [
                        {
                            'provider': service_item['provider'],
                            'startDate': service_item['startDate'],
                            'endDate': ''
                        }
                    ]
                }
            )
        }

    except:
        return {
            'statusCode': '500',
            'body': json.dumps(
                {'message': "Unable to perform request due to error. Please check structure of the body."}
            )
        }


def get_raid_handler(event, context):
    """
    
    :param event: 
    :param context: 
    :return: 
    """
    try:
        raid_handle = urllib.unquote(urllib.unquote(event["pathParameters"]["raidId"]))

    except:
        return {
            'statusCode': '400',
            'body': json.dumps(
                {
                    'message': "Incorrect path parameter type formatting for RAiD handle."
                               " Ensure it is a valid RAiD handle URL encoded string"
                }
            )
        }
    try:
        # Initialise DynamoDB
        dynamo_db = boto3.resource('dynamodb')
        raid_table = dynamo_db.Table(os.environ["RAID_TABLE"])

        # Check if RAiD exists
        query_response = raid_table.query(KeyConditionExpression=Key('handle').eq(raid_handle))

        if query_response["Count"] != 1:
            return {
                'statusCode': '400',
                'body': json.dumps(
                    {
                        'message': "Invalid RAiD handle provided in parameter path."
                                   " Ensure it is a valid RAiD handle URL encoded string"
                    }
                )
            }

        # Assign raid item to single item, since the resultwill be an array of one item
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

        return {
            'statusCode': '200',
            'body': json.dumps(raid_item)
        }

    except:
        return {
            'statusCode': '500',
            'body': json.dumps(
                {'message': "Unable to fetch RAiD due to error. Please check structure of the parameters."}
            )
        }


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
        return {
            'statusCode': '400',
            'body': json.dumps(
                {
                    'message': "Incorrect path parameter type formatting for RAiD handle."
                               " Ensure it is a URL encoded string"
                }
            )
        }

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
        return {
            'statusCode': '400',
            'body': json.dumps(
                {
                    'message': "Incorrect path parameter type formatting for RAiD handle."
                               " Ensure it is a valid RAiD handle URL encoded string"
                }
            )
        }
    try:
        # Initialise DynamoDB
        dynamo_db = boto3.resource('dynamodb')
        raid_table = dynamo_db.Table(os.environ["RAID_TABLE"])

        # Check if RAiD exists
        query_response = raid_table.query(KeyConditionExpression=Key('handle').eq(raid_handle))

        if query_response["Count"] != 1:
            return {
                'statusCode': '400',
                'body': json.dumps(
                    {
                        'message': "Invalid RAiD handle provided in parameter path."
                                   " Ensure it is a valid RAiD handle URL encoded string"
                    }
                )
            }

        # Insert association to provider index table
        provider_index_table = dynamo_db.Table(os.environ["PROVIDER_TABLE"])

        # Interpret and validate request body
        body = json.loads(event["body"])

        if "startDate" in body:
            try:
                start_date = datetime.datetime.strptime(body["startDate"], "%Y-%m-%d %H:%M:%S")
            except ValueError:
                return {
                    'statusCode': '400',
                    'body': json.dumps({'message': "Incorrect date format, should be yyyy-MM-dd hh:mm:ss"})
                }
        else:
            # Get current datetime
            start_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if "provider" not in body:
            return {
                'statusCode': '400',
                'body': json.dumps(
                    {'message': "'provider' must be provided in your request body to create an association"}
                )
            }

        # Define RAiD item
        service_item = {
            'provider': body['provider'],
            'handle': raid_handle,
            'startDate': start_date
        }

        # Send Dynamo DB put for new RAiD
        provider_index_table.put_item(Item=service_item)

        return {
            'statusCode': '200',
            'body': json.dumps(service_item)
        }

    except:
        return {
            'statusCode': '500',
            'body': json.dumps(
                {'message': "Unable to perform request due to error. Please check structure of the body."}
            )
        }


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
        return {
            'statusCode': '400',
            'body': json.dumps(
                {
                    'message': "Incorrect path parameter type formatting for RAiD handle."
                               " Ensure it is a valid RAiD handle URL encoded string"
                }
            )
        }
    # Initialise DynamoDB
    dynamo_db = boto3.resource('dynamodb')
    raid_table = dynamo_db.Table(os.environ["RAID_TABLE"])

    # Check if RAiD exists
    query_response = raid_table.query(KeyConditionExpression=Key('handle').eq(raid_handle))

    if query_response["Count"] != 1:
        return {
            'statusCode': '400',
            'body': json.dumps(
                {
                    'message': "Invalid RAiD handle provided in parameter path."
                               " Ensure it is a valid RAiD handle URL encoded string"
                }
            )
        }

    # Insert association to provider index table
    provider_index_table = dynamo_db.Table(os.environ["PROVIDER_TABLE"])

    # Interpret and validate request body
    body = json.loads(event["body"])

    if "endDate" in body:
        try:
            end_date = datetime.datetime.strptime(body["endDate"], "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return {
                'statusCode': '400',
                'body': json.dumps({'message': "Incorrect date format, should be yyyy-MM-dd hh:mm:ss"})
            }
    else:
        # Get current datetime
        end_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if "provider" not in body:
        return {
            'statusCode': '400',
            'body': json.dumps(
                {'message': "'provider' must be provided in your request body to create an association"}
            )
        }

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

    return {
        'statusCode': '200',
        'body': json.dumps(update_response["Attributes"])
    }


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
                    query_parameters["ExclusiveStartKey"] = parameters["lastEvaluatedKey"]
            except ValueError:
                return {
                    'statusCode': '400',
                    'body': json.dumps({'message': "Incorrect parameter type formatting."})
                }

        # Query table using parameters given and built to return a list of RAiDs the owner is attached too
        query_response = dynamo_db_table.query(**query_parameters)

        # Build response body
        return_body = {
            'items': query_response["Items"],
            'count': query_response["Count"],
            'scannedCount': query_response["ScannedCount"]
        }

        if 'LastEvaluatedKey' in query_response:
            return_body['lastEvaluatedKey'] = query_response["LastEvaluatedKey"]

        return {
            'statusCode': '200',
            'body': json.dumps(return_body)
        }

    except:
        return {
            'statusCode': '500',
            'body': json.dumps(
                {'message': "Unable to perform request due to error. Please check structure of the parameters."}
            )
        }
