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
import orcid
from helpers import web_helpers
from helpers import raid_helpers
from helpers import contributors_helpers
import settings

# Set Logging Level
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def process_email_queue(event, context):
    """
    Process SQS Queue messages for sending email
    :param event:
    :param context:
    :return:
    """
    try:
        # Log AWS Lambda event
        logger.info('Event: {}'.format(json.dumps(event, indent=4)))

        for record in event['Records']:
            try:
                # Load Message Body
                body = json.loads(record['body'])

                # Send SES Email
                contributors_helpers.email_contributor_invitation(
                    os.environ['SES_EMAIL_SENDER'],
                    body['recipient'],
                    body['provider'],
                    body['environment'],
                    ses_region=os.environ['SES_EMAIL_REGION']
                )

            except Exception as e:
                logger.error('Unknown error occurred.')
                logger.error(str(e))

    except Exception as e:
        logger.error('Unknown error occurred.')
        logger.error(str(e))

    logger.info('Email SQS Queue Processed...')


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
        # Get environment from the path
        logger.info('Event: {}'.format(json.dumps(event)))
        if '/demo' in event['path']:
            environment = settings.DEMO_ENVIRONMENT
        else:
            environment = settings.LIVE_ENVIRONMENT

        logger.info('Environment: {}'.format(environment))

        if environment == settings.LIVE_ENVIRONMENT:
            queue = os.environ['ORCID_INTERACTION_QUEUE']
            orcid_redirect_uri = os.environ['ORCID_REDIRECT_URL']
            orcid_institution_key = os.environ['ORCID_INSTITUTION_KEY']
            orcid_institution_secret = os.environ['ORCID_INSTITUTION_SECRET']
            orcid_sandbox = False

        else:  # Use demo queue if not in the Live environment
            queue = os.environ['DEMO_ORCID_INTERACTION_QUEUE']
            orcid_redirect_uri = os.environ['DEMO_ORCID_REDIRECT_URL']
            orcid_institution_key = os.environ['DEMO_ORCID_INSTITUTION_KEY']
            orcid_institution_secret = os.environ['DEMO_ORCID_INSTITUTION_SECRET']
            orcid_sandbox = True

        # Get the ORCID authentication code from the query string
        if event['queryStringParameters'] and 'code' in event['queryStringParameters']:
            code = event['queryStringParameters']['code']

            # Authenticate token with Orcid
            api = orcid.MemberAPI(orcid_institution_key, orcid_institution_secret, sandbox=orcid_sandbox)
            orcid_token = api.get_token_from_authorization_code(code, orcid_redirect_uri)

            # Get associated email adress of Orcid User
            orcid_person_response = api.read_record_member(
                orcid_token['orcid'],
                'person',
                orcid_token['access_token']
            )

            # Client Side Encrypt Key Values  TODO

            # Save Orcid contributor to database
            dynamo_db = boto3.resource('dynamodb')
            contributors_table = dynamo_db.Table(
                settings.get_environment_table(settings.CONTRIBUTORS_TABLE, environment)
            )
            now = raid_helpers.get_current_datetime()  # Get current datetime
            contributor = {
                'name': orcid_token['name'],
                'access_token': orcid_token['access_token'],
                'expires_in': orcid_token['expires_in'],
                'token_type': orcid_token['token_type'],
                'orcid': orcid_token['orcid'],
                'scope': orcid_token['scope'],
                'refresh_token': orcid_token['refresh_token'],
                'creationDate': now
            }

            # Save Invitation to Contributor Invitations Table
            contributors_table.put_item(Item=contributor)

            if 'emails' in orcid_person_response and 'email' in orcid_person_response['emails']:
                emails = orcid_person_response['emails']['email']

                contributor_invitation_table = dynamo_db.Table(
                    settings.get_environment_table(settings.CONTRIBUTOR_INVITATIONS_TABLE, environment)
                )

                for orcid_email in emails:
                    #  Query existing invites that need to be processed
                    logger.info('Query existing invitations for {}...'.format(orcid_email['email']))
                    contributors_invitations_query_parameters = {
                        'KeyConditionExpression': Key('email').eq(orcid_email['email']),
                        'FilterExpression': Attr('handle').exists() & Attr('processed').not_exists()
                    }

                    contributors_invitations_query_response = contributor_invitation_table.query(
                        **contributors_invitations_query_parameters
                    )

                    for invitation in contributors_invitations_query_response["Items"]:
                        # Update processed value so the invitation isn't duplicated
                        invitation['processed'] = True
                        invitation['updatedDate'] = now
                        contributor_invitation_table.put_item(Item=invitation)

                        # Send Orcid record interaction to Queue
                        invitation['orcid'] = contributor['orcid']
                        invitation['type'] = 'add'  # The type or Orcid Interaction
                        sqs_client = boto3.client('sqs')
                        send_response = sqs_client.send_message(
                            QueueUrl=queue,
                            MessageBody=json.dumps(invitation)
                        )

            return web_helpers.generate_web_redirection_response(os.environ['ORCID_AUTH_SUCCESS_URL'], event)

        else:
            logger.error('Missing querystring parameter "code".')
            return web_helpers.generate_web_redirection_response(os.environ['ORCID_AUTH_ERROR_URL'], event)

    except Exception as e:
        logger.exception('Unable to add contributor')
        return web_helpers.generate_web_redirection_response(os.environ['ORCID_AUTH_ERROR_URL'], event)


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
        provider = event['requestContext']['authorizer']['provider']

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

            # Send SES Email via Queue to reduce response time
            sqs_client = boto3.client('sqs')
            send_response = sqs_client.send_message(
                QueueUrl=os.environ['EMAILS_QUEUE'],
                MessageBody=json.dumps(
                    {
                        'recipient': body['email'],
                        'provider': provider,
                        'environment': environment
                    }
                )
            )

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

        # Initialise DynamoDB and SQS
        sqs_client = boto3.client('sqs')
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

                    # Send SES Email via Queue to reduce response time
                    send_response = sqs_client.send_message(
                        QueueUrl=os.environ['EMAILS_QUEUE'],
                        MessageBody=json.dumps(
                            {
                                'recipient': body['email'],
                                'provider': provider,
                                'environment': environment
                            }
                        )
                    )

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

                    send_response = sqs_client.send_message(
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

        contributors_query_parameters = {
            'ProjectionExpression': '#o, #a',
            'ExpressionAttributeNames': {'#o': 'orcid', '#a': 'activities'},
            'KeyConditionExpression': Key('handle').eq(raid_handle)
        }

        return web_helpers.generate_table_list_response(
            event, contributors_query_parameters,
            settings.get_environment_table(
                settings.RAID_CONTRIBUTORS_TABLE, event['requestContext']['authorizer']['environment']
            )
        )

    except Exception as e:
        logger.error('Unable to add contributor: {}'.format(e))
        return web_helpers.generate_web_body_response(
            '500',
            {'message': "Unable to get RAiD contributors.."},
            event
        )


def update_raid_contributor(event, context):
    """
    Update association of a RAiD Contributor
    :param event:
    :param context:
    :return: {"message": ""}
    """
    if 'requestContext' not in event:
        return {"message": "Warming Lambda container"}

    try:
        raid_handle = urllib.unquote(urllib.unquote(event["pathParameters"]["raidId"]))
        orcid = urllib.unquote(urllib.unquote(event["pathParameters"]["orcid"]))

    except:
        logger.error('Unable to validate RAiD or ORCID path parameter: {}'.format(sys.exc_info()[0]))
        return web_helpers.generate_web_body_response(
            '400',
            {'message': "Incorrect path parameter type formatting for RAiD handle or contributorcontributor ORCID. Ensure it is a URL encoded string"},
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

        # Check for the active contributor
        raid_contributor = contributors_helpers.get_raid_contributor(raid_handle, orcid, environment)

        if raid_contributor is None:
            return web_helpers.generate_web_body_response(
                '400',
                {
                    'message': "ORCID id does not match any contributor"
                },
                event
            )

        if any(activity['endDate'] is None for activity in raid_contributor['activities']):
            # Interpret and validate request body
            if 'body' in event and event["body"]:
                body = json.loads(event["body"])
                if 'role' not in body or 'description' not in body:
                    return web_helpers.generate_web_body_response(
                        '400',
                        {'message': 'Invalid request body: A "role" and "description" must be provided.'},
                        event
                    )

                # Send to SQS queue to process and delete Orcid Record
                sqs_client = boto3.client('sqs')
                if environment == settings.LIVE_ENVIRONMENT:
                    logger.info('Sending message on Orcid Interaction SQS Queue...')
                    queue = os.environ["ORCID_INTERACTION_QUEUE"]

                else:  # Use demo queue if not in the Live environment
                    logger.info('Sending message on Demo Orcid Interaction SQS Queue...')
                    queue = os.environ["DEMO_ORCID_INTERACTION_QUEUE"]

                message_body = {
                    'orcid': orcid,
                    'handle': raid_handle,
                    'role': body['role'],
                    'description': body['description'],
                    'provider': provider,
                    'type': 'update'
                }
                sqs_client.send_message(
                    QueueUrl=queue,
                    MessageBody=json.dumps(message_body)
                )

                return web_helpers.generate_web_body_response(
                    '200',
                    {
                        'message': 'A request to update an active Orcid member as a Contributor will be processed.'
                    },
                    event
                )

            else:
                return web_helpers.generate_web_body_response(
                    '400',
                    {'message': 'Invalid request body: A "role" and "description" must be provided.'},
                    event

                )
        else:
            return web_helpers.generate_web_body_response(
                '400',
                {
                    'message': "ORCID id does not match an active contributor"
                },
                event
            )

    except Exception as e:
        logger.error('Unable to end a contributors activity: {}'.format(e))
        return web_helpers.generate_web_body_response(
            '500',
            {'message': "Unable to update a contributor's activity..."},
            event
        )


def end_raid_contributor(event, context):
    """
    End association of a RAiD Contributor
    :param event:
    :param context:
    :return: {"message": ""}
    """
    if 'requestContext' not in event:
        return {"message": "Warming Lambda container"}

    try:
        raid_handle = urllib.unquote(urllib.unquote(event["pathParameters"]["raidId"]))
        orcid = urllib.unquote(urllib.unquote(event["pathParameters"]["orcid"]))

    except:
        logger.error('Unable to validate RAiD or ORCID path parameter: {}'.format(sys.exc_info()[0]))
        return web_helpers.generate_web_body_response(
            '400',
            {'message': "Incorrect path parameter type formatting for RAiD handle or contributorcontributor ORCID. Ensure it is a URL encoded string"},
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

        # Check for the active contributor
        raid_contributor = contributors_helpers.get_raid_contributor(raid_handle, orcid, environment)

        if raid_contributor is None:
            return web_helpers.generate_web_body_response(
                '400',
                {
                    'message': "ORCID id does not match any contributor"
                },
                event
            )

        if any(activity['endDate'] is None for activity in raid_contributor['activities']):
            # Send to SQS queue to process and delete Orcid Record
            sqs_client = boto3.client('sqs')
            if environment == settings.LIVE_ENVIRONMENT:
                logger.info('Sending message on Orcid Interaction SQS Queue...')
                queue = os.environ["ORCID_INTERACTION_QUEUE"]

            else:  # Use demo queue if not in the Live environment
                logger.info('Sending message on Demo Orcid Interaction SQS Queue...')
                queue = os.environ["DEMO_ORCID_INTERACTION_QUEUE"]

            message_body = {
                'orcid': orcid,
                'handle': raid_handle,
                'provider': provider,
                'type': 'delete'
            }
            sqs_client.send_message(
                QueueUrl=queue,
                MessageBody=json.dumps(message_body)
            )

            return web_helpers.generate_web_body_response(
                '200',
                {
                    'message': 'A request to end an active Orcid member as a Contributor will be processed.'
                },
                event
            )

        else:
            return web_helpers.generate_web_body_response(
                '400',
                {
                    'message': "ORCID id does not match an active contributor"
                },
                event
            )

    except Exception as e:
        logger.error('Unable to end a contributors activity: {}'.format(e))
        return web_helpers.generate_web_body_response(
            '500',
            {'message': "Unable to end a contributor's activity..."},
            event
        )
