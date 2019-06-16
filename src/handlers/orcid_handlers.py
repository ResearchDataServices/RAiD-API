import os
import sys
import logging
import datetime
import boto3
import json
import settings

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
                if record['eventSourceARN'] == os.environ['ORCID_INTERACTION_QUEUE']:
                    orcid_api_base_path = settings.ORCID_API_BASE_URL
                    logger.info('Production ORCID Environment')

                elif record['eventSourceARN'] == os.environ['DEMO_ORCID_INTERACTION_QUEUE']:
                    orcid_api_base_path = settings.ORCID_SANDBOX_API_BASE_URL
                    logger.info('Sandbox ORCID Environment')

                else:
                    logger.error('Unknown Queue Origin')
                    continue

                logger.info('ORCID API call will use Base Url: {}'.format(orcid_api_base_path))

                # Process new message
                body = json.loads(record['body'])

                if body['type'] == 'add':
                    logger.info('Adding a new ORCID Record...')
                    # TODO Add RAiD info to Contributors Orcid Activities

                elif body['type'] == 'update':
                    logger.info('Updating an ORCID Record...')
                    # TODO Update RAiD info to Contributors Orcid Activities using the PutId

                else:
                    logger.error('Unknown Queue Origin')
                    continue

            except Exception as e:
                logger.error('Unknown error occurred.')
                logger.error(str(e))

    except Exception as e:
        logger.error('Unknown error occurred.')
        logger.error(str(e))

    logger.info('Orcid SQS Queue Processed...')
