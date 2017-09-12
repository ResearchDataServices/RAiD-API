from __future__ import print_function

import os
import datetime
import boto3
import json
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


def get_owner_raids_handler(event, context):
    """
    Return RAiDs associated to the authenticated owner with optional parameters for filter and search options
    :param event: 
    :param context: 
    :return: 
    """
    try:
        # Initialise DynamoDB
        dynamo_db = boto3.resource('dynamodb')
        raid_table = dynamo_db.Table(os.environ["RAID_TABLE"])

        query_parameters = {
            'IndexName': 'OwnerIndex',
            'KeyConditionExpression': Key('owner').eq(event['requestContext']['authorizer']['provider'])
        }

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

        # Query table using secondary index to return a list of RAiDs the owner is attached too
        query_response = raid_table.query(**query_parameters)

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
