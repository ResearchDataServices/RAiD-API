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
    :param context: AWS context object that must at least contain a 'provider' string.
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
                            'endDate': ''}
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
