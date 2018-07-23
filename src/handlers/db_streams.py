import os
import sys
import logging
import datetime
import boto3
from boto3.dynamodb.types import TypeDeserializer
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError
import json
from helpers import ands_helpers
import settings

# Set Logging Level
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def raid_table_dynamodb_stream_event(event, context):
    """
    Process event log of DynamoDB stream and update ANDS handle content path if needed
    :param event:
    :param context:
    :return:
    """
    try:
        # Log AWS Lambda event
        logger.info('Event: {}'.format(json.dumps(event, indent=4)))
        for record in event['Records']:
            # Convert low-level DynamoDB format to Python dictionary
            deserializer = TypeDeserializer()
            table_keys = {k: deserializer.deserialize(v) for k, v in record['dynamodb']['Keys'].items()}
            table_attributes = {k: deserializer.deserialize(v) for k, v in record['dynamodb']['NewImage'].items()}

            if record['eventSourceARN'] == os.environ['DEMO_RAID_STREAM_ARN']:
                ands_url_path = "{}modifyValueByIndex?handle={}&value={}&index={}".format(
                    os.environ["DEMO_ANDS_SERVICE"],
                    table_keys['handle'],
                    table_attributes['contentPath'],
                    table_attributes['contentIndex']
                )

                ands_secret = os.environ["ANDS_DEMO_SECRET"]

            elif record['eventSourceARN'] == os.environ['RAID_STREAM_ARN']:
                ands_url_path = "{}modifyValueByIndex?handle={}&value={}&index={}".format(
                    os.environ["ANDS_SERVICE"],
                    table_keys['handle'],
                    table_attributes['contentPath'],
                    table_attributes['contentIndex']
                )

                ands_secret = os.environ["ANDS_SECRET"]

            else:
                logger.info('Unknown DynamoDB Stream')
                continue

            # Process new records
            if record['eventName'] == 'INSERT':
                # Skip if default Raid
                if table_attributes['contentPath'] == settings.RAID_SITE_URL:
                    logger.info('Not updating content path "{}" on new RAiD as it is the default: {}'.format(
                        table_attributes['contentPath'], table_keys['handle'])
                    )
                    continue

                logger.info('Updating content path "{}" on new RAiD: {}'.format(
                    table_attributes['contentPath'], table_keys['handle'])
                )

                ands_mint = ands_helpers.ands_handle_request(
                    ands_url_path,
                    os.environ["ANDS_APP_ID"],
                    "raid",
                    "raid.org.au",
                    ands_secret,
                )

                logger.info(json.dumps(ands_mint))

            elif record['eventName'] == 'MODIFY':
                old_table_attributes = {
                    k: deserializer.deserialize(v) for k, v in record['dynamodb']['OldImage'].items()
                }

                # Update handle content Path if it is different
                if old_table_attributes['contentPath'] != table_attributes['contentPath']:
                    logger.info('Updating content path "{}" on existing RAiD: {}'.format(
                        table_attributes['contentPath'], table_keys['handle'])
                    )

                    ands_mint = ands_helpers.ands_handle_request(
                        ands_url_path,
                        os.environ["ANDS_APP_ID"],
                        "raid",
                        "raid.org.au",
                        ands_secret,
                    )

                    logger.info(json.dumps(ands_mint))

                else:
                    logger.info('Existing RAiD has no changes to content path.')

    except Exception as e:
        logger.error('Unknown error occurred.')
        logger.error(str(e))

    logger.info('DynamoDB Stream Processed...')
