import os
import sys
import logging
import datetime
import boto3
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError
import json
import settings


def prettify_raid_contributors_list(db_items):
    """
    Convert sort key concatenated RAiD Contributor to a human-readable version
    :param db_items: Items return for the DynamoDB Query or Scan
    :return:
    """
    items = [{
        'orcid': '-'.join(item['orcid-startDate'].split('-')[:4]),
        'startDate': '-'.join(item['orcid-startDate'].split('-')[4:]),
        'endDate': None if 'endDate' not in item else item['endDate'],
        'provider': item['provider'],
        'role': item['role'],
        'description': item['description']
    } for item in db_items]

    return items


def get_contributor(orcid, environment='demo'):
    """
    Get an Orcid user that has given RAiD permission to act on behalf
    :param orcid:
    :param environment:
    :return:
    """
    # Initialise DynamoDB
    dynamo_db = boto3.resource('dynamodb')

    contributors_table = dynamo_db.Table(
        settings.get_environment_table(settings.CONTRIBUTORS_TABLE, environment)
    )

    contributors_query_response = contributors_table.query(KeyConditionExpression=Key('orcid').eq(orcid))

    if contributors_query_response["Count"] < 1:
        return None

    # Assign contributor item to single item, since the result will be an array of one item
    contributor = contributors_query_response['Items'][0]

    return contributor


def get_raid_contributor(handle, orcid, start_date, environment='demo'):
    """
    Query the RAiD Contributors for an active contributor
    :param handle: RAiD Handle
    :param orcid: The Orcid User
    :param start_date: The data of association
    :param environment: The environment: 'demo' or' live'
    :return:
    """
    # Initialise DynamoDB
    dynamo_db = boto3.resource('dynamodb')

    raid_contributors_table = dynamo_db.Table(
        settings.get_environment_table(settings.RAID_CONTRIBUTORS_TABLE, environment)
    )

    contributor_sort_key = '{}-{}'.format(orcid, start_date)

    raid_contributors_query_response = raid_contributors_table.query(
        KeyConditionExpression=Key('handle').eq(handle) & Key('orcid-startDate').eq(contributor_sort_key)
    )

    if raid_contributors_query_response["Count"] < 1:
        return None

    # Assign raid contributor to single item, since the result will be an array of one item
    raid_contributor = raid_contributors_query_response['Items'][0]

    return raid_contributor


def create_or_update_raid_contributor(request_body, put_code, environment='demo'):
    """
    Create a RAiD Contributor association from a request body
    :param request_body:
    :param put_code:
    :param environment:
    :return:
    """
    # Initialise DynamoDB
    dynamo_db = boto3.resource('dynamodb')

    raid_contributors_table = dynamo_db.Table(
        settings.get_environment_table(settings.RAID_CONTRIBUTORS_TABLE, environment)
    )
    raid_contributor = {
        'handle': request_body['handle'],
        'orcid-startDate': '{}-{}'.format(request_body['orcid'], request_body['startDate']),
        'provider': request_body['provider'],
        'role': request_body['role'],
        'description': request_body['description'],
        'putCode': put_code
    }

    # Save RAiD Contributor Association to DynamoDB
    raid_contributors_table.put_item(Item=raid_contributor)
