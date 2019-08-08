import os
import sys
import logging
import traceback
import datetime
import base64
import boto3
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError
import json
import orcid
import settings
from helpers import orcid_helpers
from helpers import contributors_helpers

# Set Logging Level
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def process_queue(event, context):
    """
    Process SQS Queue messages for ORCID Interactions
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

                if record['eventSourceARN'] == os.environ['ORCID_INTERACTION_QUEUE']:
                    environment = settings.LIVE_ENVIRONMENT
                    logger.info('Production ORCID Environment')

                elif record['eventSourceARN'] == os.environ['DEMO_ORCID_INTERACTION_QUEUE']:
                    environment = settings.DEMO_ENVIRONMENT
                    logger.info('Sandbox ORCID Environment')

                else:
                    logger.error('Unknown Queue Origin')
                    continue

                # Get Orcid member details from DynamoDB
                contributor = contributors_helpers.get_contributor(
                    body['orcid'], environment
                )

                if contributor is None:
                    logger.error('This Orcid user has not granted RAiD permission to be associated.')
                    continue

                # Check for existing RAiD Contributor
                raid_contributor = contributors_helpers.get_raid_contributor(
                    body['handle'], contributor['orcid'], environment=environment
                )

                # Client-side encrypt token values
                kms = boto3.client('kms')
                access_token_decoded = base64.b64decode(contributor['access_token'])
                decrypt_access_token = kms.decrypt(CiphertextBlob=access_token_decoded)
                access_token = decrypt_access_token[u'Plaintext']

                # Create Orcid Member API object and request body
                api = orcid_helpers.get_orcid_api_object(environment=environment)

                if body['type'] == 'add' or body['type'] == 'update':
                    orcid_json = orcid_helpers.queue_record_to_orcid_request_object(body)

                    # Process Orcid CRUD
                    if body['type'] == 'add':
                        logger.info('Adding a new ORCID Record for id:{}...'.format(contributor['orcid']))

                        if raid_contributor is not None and any(activity['endDate'] is None for activity in raid_contributor['activities']):
                            logger.error('This Orcid user is already an active contributor.')
                            continue

                        # Send request to Orcid
                        put_code = api.add_record(contributor['orcid'], access_token, 'work', orcid_json)

                        # Save new contributor association to DynamoDB
                        contributors_helpers.create_raid_contributor(body, put_code, environment=environment)

                    elif body['type'] == 'update':
                        # Update new contributor association to DynamoDB
                        logger.info('Updating an ORCID Record for id:{}...'.format(contributor['orcid']))
                        contributors_helpers.update_raid_contributor(
                            body, raid_contributor, environment=environment
                        )

                        # Send request to Orcid
                        put_code = raid_contributor['putCode']
                        api.update_record(
                            contributor['orcid'], access_token, 'work', orcid_json, put_code
                        )

                elif body['type'] == 'delete':
                    logger.info('Ending an ORCID Record association for id:{}...'.format(contributor['orcid']))
                    if raid_contributor is not None and any(
                            activity['endDate'] is None for activity in raid_contributor['activities']):
                        # Update DynamoDB Entry
                        contributors_helpers.end_raid_contributor(raid_contributor, environment)

                        # Send request to Orcid
                        put_code = raid_contributor['putCode']
                        api.remove_record(contributor['orcid'], access_token, 'work', put_code)

                    else:
                        logger.error('This Orcid user is not an active contributor.')
                        continue

                else:
                    logger.error('Unknown type')
                    continue

            except Exception as e:
                logger.exception('Unknown error occurred.')
                logger.error(str(e))

    except Exception as e:
        logger.exception('Unknown error occurred.')
        logger.error(str(e))

    logger.info('Orcid SQS Queue Processed...')

