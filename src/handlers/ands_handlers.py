import os
import sys
import logging
import datetime
import boto3
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError
import json
import urllib
from helpers import web_helpers
from helpers import ands_helpers
from helpers import raid_helpers
import settings

# Set Logging Level
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Maxium amount of handles needed in a queue
DEFAULT_HANDLE_THRESHOLD = 20


def create_ands_handles_from_event(event, context):
    """
    Mint new ANDS handle for queue that is in a low threshold
    :param event:
    :param context:
    :return:
    """
    logger.info(json.dumps(event))

    # If CloudWatch event AndsHandleAlarmTopic
    if 'Records' in event:
        for record in event['Records']:

            # SNS Alarm
            if record['EventSource'] == "aws:sns" and 'ALARM' in record['Sns']['Subject']:

                # ANDS Handle Alarm
                if record['Sns']['TopicArn'] == os.environ['ANDS_HANDLE_ALARM_TOPIC']:
                    logger.info('ANDS Handle Queue below threshold...')
                    queue = os.environ["ANDS_HANDLES_QUEUE"]
                    service_url = os.environ["ANDS_SERVICE"]

                # Demo ANDS Handle Alarm
                elif record['Sns']['TopicArn'] == os.environ['DEMO_ANDS_HANDLE_ALARM_TOPIC']:
                    logger.info('DEMO_ANDS Handle Queue below threshold...')
                    queue = os.environ["DEMO_ANDS_HANDLES_QUEUE"]
                    service_url = os.environ["DEMO_ANDS_SERVICE"]

                else:
                    raise Exception('Unknown SNS Alarm event')

                # ANDS Minting URL (All have the same temp content path)
                ands_url_path = "{}mint?type=URL&value={}".format(
                    service_url, settings.RAID_SITE_URL
                )

                # Create enough messages to put queue into a safe threshold
                if 'SAFE_HANDLE_THRESHOLD' in os.environ:
                    threshold = os.environ['SAFE_HANDLE_THRESHOLD']
                else:
                    threshold = DEFAULT_HANDLE_THRESHOLD

                for i in range(0, threshold):
                    logger.info('Minting ANDS Handle: {}'.format(i + 1))

                    # Mint ANDS Handle
                    ands_mint = ands_helpers.ands_handle_request(
                        ands_url_path,
                        os.environ["ANDS_APP_ID"],
                        "raid",
                        "raid.org.au",
                        os.environ["ANDS_SECRET"],
                    )

                    # Send new ANDS handle to SQS
                    SQS_client = boto3.client('sqs')
                    send_response = SQS_client.send_message(
                        QueueUrl=queue,
                        MessageBody=json.dumps(ands_mint)
                    )

                    # TODO creating matching DynamoDB item for archiving

            else:
                logger.info('Unrecognized AWS event record.')
    else:
        logger.info('Non-standard event.')
