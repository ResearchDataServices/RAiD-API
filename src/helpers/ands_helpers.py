import requests
import logging
import json
import base64
from xml.etree import ElementTree
import settings
import boto3

# Set Logging Level
logger = logging.getLogger()
logger.setLevel(logging.INFO)


class AndsMintingError(Exception):
    """
    Exception used for an unsuccessful content path and handle minting
    """
    pass


def build_basic_authorized_mint_body(identifier, auth_domain):
    xml_data = """
                <request name="mint">
                    <properties>
                        <property name="identifier" value="{}"/>
                        <property name="authDomain" value="{}"/>
                    </properties>
                </request>
                """.format(identifier, auth_domain)
    return xml_data


def build_ip_whitelist_mint_body(app_id, identifier, auth_domain):
    xml_data = """
                <request name="mint">
                    <properties>
                        <property name="appId" value="{}"/>
                        <property name="identifier" value="{}"/>
                        <property name="authDomain" value="{}"/>
                    </properties>
                </request>
                """.format(app_id, identifier, auth_domain)
    return xml_data


def build_internal_authorized_mint_body(app_id, shared_secret, identifier, auth_domain):
    xml_data = """
                <request name="mint">
                    <properties>
                        <property name="appId" value="{}"/>
                        <property name="sharedSecret" value="{}"/>
                        <property name="identifier" value="{}"/>
                        <property name="authDomain" value="{}"/>
                    </properties>
                </request>
                """.format(app_id, shared_secret, identifier, auth_domain)
    return xml_data


def ands_handle_request(url_path, app_id, identifier, auth_domain, shared_secret=None):
    """
    Build a minting (create/update) query for ANDS and parse XML response
    :param url_path:
    :param app_id:
    :param shared_secret:
    :param identifier:
    :param auth_domain:
    :return:
    """

    # Build Headers
    headers = {'Content-Type': 'application/xml'}

    if shared_secret and ('https://demo.ands.org.au' not in url_path):  # Basic Authenticated call
        # Create XML Body
        xml_data = build_basic_authorized_mint_body(identifier, auth_domain)

        # Build Headers
        encoded_app_secret = base64.b64encode('{}:{}'.format(app_id, shared_secret))
        authorization = 'Basic {}'.format(encoded_app_secret)
        headers['Authorization'] = authorization

    else:  # IP Address Whitelisted call
        # Create XML Body
        xml_data = build_ip_whitelist_mint_body(app_id, identifier, auth_domain)

    # Process response
    response = requests.post(url_path, data=xml_data, headers=headers)
    xml_tree = ElementTree.fromstring(response.content)

    # Get result of root XML tag response and read all child tags into a to dictionary
    if xml_tree.attrib["type"] == "success":
        response_data = {
            "handle": xml_tree.find("identifier").attrib["handle"],
            "contentIndex": xml_tree.find("identifier/property").attrib["index"],
            "timestamp": xml_tree.find("timestamp").text,
            "message": xml_tree.find("message").text
        }
        return response_data

    else:
        raise AndsMintingError(
            "Unable to mint content path for an ANDS handle.\n"
            "URL: \n"
            "{} \n"
            "Headers: \n"
            "{} \n"
            "Request: \n"
            "{} \n"
            "Response: \n"
            "{}\n".format(url_path, headers, xml_data, response.text)
        )


def get_new_ands_handle(environment, live_queue, demo_queue, ands_service,
                        ands_demo_service, content_path, ands_app_id,
                        ands_secret=None):
    """
    Get an ANDS handle from the relevant queue, falling back to a freshly
    minted on from ANDS directly.

    :param environment:
    :param live_queue:
    :param demo_queue:
    :param ands_service:
    :param ands_demo_service:
    :param content_path:
    :param ands_app_id:
    :param ands_secret:
    :return:
    """

    sqs_client = boto3.client('sqs')
    if environment == settings.DEMO_ENVIRONMENT:
        queue_url = demo_queue
    elif environment == settings.LIVE_ENVIRONMENT:
        queue_url = live_queue

    logger.info('ANDS Handle Queue URL:{}'.format(queue_url))

    sqs_receive_response = sqs_client.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1)

    # Use ANDS minted handle from Queue if there is one
    if 'Messages' in sqs_receive_response and sqs_receive_response['Messages'] > 0:
        handle_message = sqs_receive_response['Messages'][0]
        logger.info('SQS Response:{}'.format(json.dumps(handle_message)))
        message_body = json.loads(handle_message['Body'])
        ands_handle = message_body["handle"]
        ands_content_index = message_body["contentIndex"]

        # Delete from SQS Queue
        sqs_delete_response = sqs_client.delete_message(
            QueueUrl=queue_url,
            ReceiptHandle=handle_message['ReceiptHandle']
        )

    # No Handle exists and one must be created synchronously with ANDS
    else:
        logger.info('SQS Response: No Available ANDS Handles. Creating one synchronously with ANDS...')

        if environment == settings.DEMO_ENVIRONMENT:
            ands_url_path = "{}mint?type=URL&value={}".format(
                ands_demo_service, content_path
            )
        elif environment == settings.LIVE_ENVIRONMENT:
            ands_url_path = "{}mint?type=URL&value={}".format(
                ands_service, content_path
            )

        ands_mint = ands_handle_request(
            ands_url_path,
            ands_app_id,
            "raid",
            "raid.org.au",
            ands_secret,
        )

        ands_handle = ands_mint["handle"]
        ands_content_index = ands_mint["contentIndex"]

    return ands_handle, ands_content_index
