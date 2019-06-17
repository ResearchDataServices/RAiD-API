import os
import sys
import logging
import datetime
import base64
import boto3
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError
import json
import urllib
from helpers import web_helpers
from helpers import raid_helpers
from helpers import contributors_helpers
import settings

# Set Logging Level
logger = logging.getLogger()
logger.setLevel(logging.ERROR)


def authenticate_contributor(event, context):
    """
    Authenticate an Orcid contributor's code and save credentials to database
    :param event:
    :param context:
    :return: {"message": ""}
    """
    if 'requestContext' not in event:
        return {"message": "Warming Lambda container"}

    try:
        # Initialise DynamoDB
        dynamo_db = boto3.resource('dynamodb')

        # TODO sandbox or normal environment?
        # contributor_invitation_table = dynamo_db.Table(
        #     settings.get_environment_table(settings.CONTRIBUTOR_INVITATIONS_TABLE, environment)
        # )
        #
        # contributors_table = dynamo_db.Table(
        #     settings.get_environment_table(settings.CONTRIBUTORS_TABLE, environment)
        # )

        # Interpret and validate request body
        if 'body' in event and event["body"]:
            body = json.loads(event["body"])

            if 'code' not in body:
                return web_helpers.generate_web_body_response(
                    '400',
                    {'message': 'Invalid request body: A "code" must be provided.'},
                    event
                )

            # TODO Orcid interaction to authenticate token
            return web_helpers.generate_web_body_response(
                '200',
                {'message': 'Success: Orcid integration with RAiD completed.'},
                event
            )

        else:
            return web_helpers.generate_web_body_response(
                '400',
                {'message': 'Invalid request body: A "code" must be provided.'},
                event

            )

    except Exception as e:
        logger.error('Unable to add contributor: {}'.format(e))
        return web_helpers.generate_web_body_response(
            '400',
            {'message': "Unable to authenticate contributor token. Please check structure of the JSON body."},
            event
        )


def invite_contributor(event, context):
    """
    Invite a contributor to the RAiD service via email
    :param event:
    :param context:
    :return: {"message": ""}
    """
    if 'requestContext' not in event:
        return {"message": "Warming Lambda container"}

    try:
        environment = event['requestContext']['authorizer']['environment']

        # Initialise DynamoDB
        dynamo_db = boto3.resource('dynamodb')

        # Interpret and validate request body
        if 'body' in event and event["body"]:
            body = json.loads(event["body"])

            if 'email' not in body:
                return web_helpers.generate_web_body_response(
                    '400',
                    {'message': 'Invalid request body: An "email" must be provided.'},
                    event
                )

            # Create core contributor item for invitation or Orcid record processing
            now = raid_helpers.get_current_datetime()  # Get current datetime
            contributor_item = {'creationDate': now, 'email': body['email']}

            contributor_invitation_table = dynamo_db.Table(
                settings.get_environment_table(settings.CONTRIBUTOR_INVITATIONS_TABLE, environment)
            )

            # Check if there is an existing invitation
            query_response = contributor_invitation_table.query(
                KeyConditionExpression=Key('email').eq(body['email'])
            )

            if query_response["Count"] > 0:
                return web_helpers.generate_web_body_response('400', {
                    'message': "There is an existing invitation to this contributor."}, event)

            # Save Invitation to Contributor Invitations Table
            contributor_invitation_table.put_item(Item=contributor_item)

            # TODO Send SES Email
            return web_helpers.generate_web_body_response(
                '200',
                {'message': 'An email invite has been sent to the contributor.'},
                event
            )

        else:
            return web_helpers.generate_web_body_response(
                '400',
                {'message': 'Invalid request body: An "email" must be provided.'},
                event

            )

    except Exception as e:
        logger.error('Unable to add contributor: {}'.format(e))
        return web_helpers.generate_web_body_response(
            '400',
            {'message': "Unable to invite contributor. Please check structure of the JSON body."},
            event
        )


def add_contributor(event, context):
    """
    Add/Invite a contributor to a RAiD via email or an existing active Orcid user
    :param event:
    :param context:
    :return: {"message": ""}
    """
    if 'requestContext' not in event:
        return {"message": "Warming Lambda container"}

    try:
        raid_handle = urllib.unquote(urllib.unquote(event["pathParameters"]["raidId"]))

    except:
        logger.error('Unable to validate RAiD parameter: {}'.format(sys.exc_info()[0]))
        return web_helpers.generate_web_body_response(
            '400',
            {'message': "Incorrect path parameter type formatting for RAiD handle. Ensure it is a URL encoded string"},
            event
        )

    try:
        environment = event['requestContext']['authorizer']['environment']
        provider = event['requestContext']['authorizer']['provider']

        # Initialise DynamoDB
        dynamo_db = boto3.resource('dynamodb')
        raid_table = dynamo_db.Table(
            settings.get_environment_table(settings.RAID_TABLE, environment)
        )
        # Check if RAiD exists
        query_response = raid_table.query(KeyConditionExpression=Key('handle').eq(raid_handle))

        if query_response["Count"] != 1:
            return web_helpers.generate_web_body_response('400', {
                'message': "Invalid RAiD handle provided in parameter path. "
                           "Ensure it is a valid RAiD handle URL encoded string"}, event)

        # Assign raid item to single item, since the result will be an array of one item
        raid_item = query_response['Items'][0]

        # Interpret and validate request body
        if 'body' in event and event["body"]:
            body = json.loads(event["body"])

            if ('email' in body) and ('orcid' in body) or ('email' not in body) and ('orcid' not in body):
                return web_helpers.generate_web_body_response(
                    '400',
                    {'message': 'Invalid request body: Either an "email" or "orcid" must be provided.'},
                    event
                )

            elif 'email' or 'orcid' in body:
                # Create core contributor item for invitation or Orcid record processing
                now = raid_helpers.get_current_datetime()  # Get current datetime
                contributor_item = {'creationDate': now, 'handle': raid_handle, 'provider': provider}

                if "startDate" in body:  # Default to the current data and time
                    try:
                        start_date = body["startDate"]
                        datetime.datetime.strptime(start_date, "%Y-%m-%d %H:%M:%S")
                        contributor_item['startDate'] = start_date

                    except ValueError as e:
                        logger.error('Unable to capture date: {}'.format(e))
                        return web_helpers.generate_web_body_response('400', {
                            'message': "Incorrect date format, should be yyyy-MM-dd hh:mm:ss"}, event)

                else:
                    contributor_item['startDate'] = raid_helpers.get_current_datetime()

                if "role" in body:  # Default to "Contributor"
                    contributor_item['role'] = body['role']
                else:
                    contributor_item['role'] = 'Contributor'

                if "description" in body:  # Default to the existing RAiD Description
                    contributor_item['description'] = body['description']
                else:
                    contributor_item['description'] = 'Contributor to the RAiD project "{}"'.format(
                        raid_item['meta']['name'])

                if 'email' in body:  # Invite a contributor to a RAiD and the
                    contributor_invitation_table = dynamo_db.Table(
                        settings.get_environment_table(settings.CONTRIBUTOR_INVITATIONS_TABLE, environment)
                    )

                    # Check if there is an existing invitation
                    query_response = contributor_invitation_table.query(
                        KeyConditionExpression=Key('email').eq(body['email']),
                        FilterExpression=Attr('handle').eq(raid_handle)
                    )

                    if query_response["Count"] > 0:
                        return web_helpers.generate_web_body_response('400', {
                            'message': "There is an existing invitation to this contributor."}, event)

                    # Save Invitation to Contributor Invitations Table
                    contributor_item['email'] = body['email']
                    contributor_invitation_table.put_item(Item=contributor_item)

                    # TODO Send SES Email
                    return web_helpers.generate_web_body_response(
                        '200',
                        {'message': 'An email invite has been sent to the contributor.'},
                        event
                    )

                else:  # Invite a contributor to a RAiD via their integrated orcid
                    contributors_table = dynamo_db.Table(
                        settings.get_environment_table(settings.CONTRIBUTORS_TABLE, environment)
                    )

                    # Check it is an active Orcid user
                    query_response = contributors_table.query(
                        KeyConditionExpression=Key('orcid').eq(body['orcid'])
                    )

                    if query_response["Count"] < 1:
                        return web_helpers.generate_web_body_response('400', {
                            'message': "This Orcid user has not granted RAiD permission to be associated."}, event)

                    contributor_item['orcid'] = body['orcid']
                    contributor_item['type'] = 'add'  # The type or Orcid Interaction

                    # Send contributor information to SQS Queue
                    if environment == settings.LIVE_ENVIRONMENT:
                        logger.info('Sending message on Orcid Interaction SQS Queue...')
                        queue = os.environ["ORCID_INTERACTION_QUEUE"]

                    else:  # Use demo queue if not in the Live environment
                        logger.info('Sending message on Demo Orcid Interaction SQS Queue...')
                        queue = os.environ["DEMO_ORCID_INTERACTION_QUEUE"]

                    SQS_client = boto3.client('sqs')
                    send_response = SQS_client.send_message(
                        QueueUrl=queue,
                        MessageBody=json.dumps(contributor_item)
                    )

                    return web_helpers.generate_web_body_response(
                        '200',
                        {'message': 'A request to add active Orcid member as a Contributor will be processed.'},
                        event
                    )

            else:
                return web_helpers.generate_web_body_response(
                    '400',
                    {'message': 'Invalid request body: Either an "email" or "orcid" must be provided.'},
                    event
                )

        else:
            return web_helpers.generate_web_body_response(
                '400',
                {'message': 'Invalid request body: Either an "email" or "orcid" must be provided.'},
                event

            )

    except Exception as e:
        logger.error('Unable to add contributor: {}'.format(e))
        return web_helpers.generate_web_body_response(
            '400',
            {'message': "Unable to add contributor. Please check structure of the JSON body."},
            event
        )


def get_raid_contributors(event, context):
    """
    Get a list of contributors of a RAiD
    :param event:
    :param context:
    :return: {"message": ""}
    """
    if 'requestContext' not in event:
        return {"message": "Warming Lambda container"}

    try:
        raid_handle = urllib.unquote(urllib.unquote(event["pathParameters"]["raidId"]))

    except:
        logger.error('Unable to validate RAiD parameter: {}'.format(sys.exc_info()[0]))
        return web_helpers.generate_web_body_response(
            '400',
            {'message': "Incorrect path parameter type formatting for RAiD handle. Ensure it is a URL encoded string"},
            event
        )

    try:
        environment = event['requestContext']['authorizer']['environment']
        provider = event['requestContext']['authorizer']['provider']

        # Initialise DynamoDB
        dynamo_db = boto3.resource('dynamodb')
        raid_table = dynamo_db.Table(
            settings.get_environment_table(settings.RAID_TABLE, environment)
        )
        # Check if RAiD exists
        query_response = raid_table.query(KeyConditionExpression=Key('handle').eq(raid_handle))

        if query_response["Count"] != 1:
            return web_helpers.generate_web_body_response('400', {
                'message': "Invalid RAiD handle provided in parameter path. "
                           "Ensure it is a valid RAiD handle URL encoded string"}, event)

        # Assign raid item to single item, since the result will be an array of one item
        raid_item = query_response['Items'][0]

        provider_query_parameters = {
            'ProjectionExpression': "#o, #d, #r, provider, endDate",
            'ExpressionAttributeNames': {"#o": "orcid-startDate", "#r": "role", "#d": "description"},
            'KeyConditionExpression': Key('handle').eq(raid_handle)
        }

        return web_helpers.generate_table_list_response(
            event, provider_query_parameters,
            settings.get_environment_table(
                settings.RAID_CONTRIBUTORS_TABLE, event['requestContext']['authorizer']['environment']
            ),
            transformation_method=contributors_helpers.prettify_raid_contributors_list
        )

    except Exception as e:
        logger.error('Unable to add contributor: {}'.format(e))
        return web_helpers.generate_web_body_response(
            '500',
            {'message': "Unable to get RAiD contributors.."},
            event
        )
