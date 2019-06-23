import os
import sys
import logging
import datetime
import boto3
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError
import json
import settings


def email_contributor_invitation(sender, recipient, invitor, environment, charset='UTF-8',
                                 ses_region='us-west-2'):
    """
    Email an invitation to the RAiD service and Handle inf provided
    :param sender:
    :param recipient:
    :param invitor:
    :param environment:
    :param charset:
    :param ses_region:
    :return:
    """
    subject = 'RAiD Contributor Invitation'
    if environment == settings.LIVE_ENVIRONMENT:
        orcid_uri = settings.ORCID_API_BASE_URL
        client_id = os.environ['DEMO_ORCID_INSTITUTION_KEY']
        redirect_uri = os.environ['ORCID_REDIRECT_URL']
    else:
        orcid_uri = settings.ORCID_SANDBOX_API_BASE_URL
        client_id = os.environ['ORCID_INSTITUTION_KEY']
        redirect_uri = os.environ['DEMO_ORCID_REDIRECT_URL']

    # The email body for recipients with non-HTML email clients.
    body_text = (
        "Welcome.\r\n"
        "You have been invited by '{0}' to the RAiD Service. A RAiD is a handle (a string of numbers) that "
        "is persistent and can have other digital Identifiers associated with it to trace all of the "
        "researchers, institutions, outputs, tools and services that are used in a project.\r\n"
        "RAiD integrates with ORCID to associate an individual's contributions to a project using their "
        "globally unique ORCID ID. In order to do this, the RAiD Service requires you to accept it as an "
        "ORCID Trusted Service with permission's to view your associated email addresses and create records "
        "on your behalf. In order for integration with ORCiD to be effective, you will need to have this "
        "email address associated with it (primary or related) so that you can be associated to a RAiD via "
        "the email address '{0}' is familiar with.\r\n"     
        "Please follow the link below to login or register with ORCID:\r\n"
        "{1}/oauth/authorize?client_id={2}&response_type=code&scope=/activities/update&redirect_uri={3}"
        "\r\n"
        "Kind Regards,\r\n"
        "The RAiD Service team.\r\n"
    ).format(invitor, orcid_uri, client_id, redirect_uri)

    # The HTML body of the email.
    body_html = """
    <html>
    <head></head>
    <body>
        Welcome.
        <br>
        <br>You have been invited by '<i>{0}</i>' to the <i><a href="https://www.raid.org.au/" target="_blank">RAiD Service</a>.</i> A <i>RAiD</i> is a handle (a string of numbers) that is persistent and can have other digital Identifiers associated with it to trace all of the researchers, institutions, outputs, tools and services that are used in a project.
        <br>
        <br>
        <i>RAiD</i> integrates with <i><a href="https://orcid.org/" target="_blank">ORCID</a></i> to associate an individual's contributions to a project using their globally unique ORCID ID. In order to do this, the <i>RAiD Service</i> requires you to accept it as an <i>ORCID</i> Trusted Service with permission's to view your associated email addresses and create records on your behalf. In order for integration with <i>ORCiD</i> to be effective, you will need to have this email address associated with it (primary or related) so that you can be associated to a <i>RAiD</i> via the email address '<i>{0}</i>' is familiar with.
        <br>
        <br>
        Please follow the link below to login or register with <i>ORCID</i>:
        <br>
        <a href="{1}/oauth/authorize?client_id={2}&response_type=code&scope=/activities/update&redirect_uri={3}" target="_blank">
            {1}/oauth/authorize?client_id={2}&response_type=code&scope=/activities/update&redirect_uri={3} 
        </a>
        <br>
        <br>
        Kind Regards,
        <br>
        The RAiD Service team.
    </body>
    </html>
     """.format(invitor, orcid_uri, client_id, redirect_uri)

    # Create a new SES resource and specify a region.
    client = boto3.client('ses', region_name=ses_region)

    # Send the email.
    # Provide the contents of the email.
    response = client.send_email(
        Destination={
            'ToAddresses': [recipient],
        },
        Message={
            'Body': {
                'Html': {
                    'Charset': charset,
                    'Data': body_html,
                },
                'Text': {
                    'Charset': charset,
                    'Data': body_text,
                },
            },
            'Subject': {
                'Charset': charset,
                'Data': subject,
            },
        },
        Source=sender
    )


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
