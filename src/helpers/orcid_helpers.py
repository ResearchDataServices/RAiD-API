import urllib
import json
import os
import sys
import datetime
import orcid
import settings


def get_orcid_api_object(environment='demo', type='member'):
    """
    Get an Orcid API object using the correct keys and api type
    :param environment:
    :param type:
    :return:
    """
    if environment == settings.LIVE_ENVIRONMENT:
        orcid_sandbox = False
        orcid_institution_key = os.environ['ORCID_INSTITUTION_KEY']
        orcid_institution_secret = os.environ['ORCID_INSTITUTION_SECRET']

    elif environment == settings.DEMO_ENVIRONMENT:
        orcid_sandbox = True
        orcid_institution_key = os.environ['DEMO_ORCID_INSTITUTION_KEY']
        orcid_institution_secret = os.environ['DEMO_ORCID_INSTITUTION_SECRET']

    else:
        return None

    if type == 'member':
        api = orcid.MemberAPI(
            orcid_institution_key,
            orcid_institution_secret,
            sandbox=orcid_sandbox
        )

    else:
        api = orcid.PublicAPI(
            orcid_institution_key,
            orcid_institution_secret,
            sandbox=orcid_sandbox
        )

    return api


def queue_record_to_orcid_request_object(queue_record, environment='demo'):
    """
    Convert a queue record which represents an Orcid interaction to a Orcid
    API Json compatible body.
    :param queue_record: A record from the SQS CloudWatch Event Records
    object {'Records' : []}
    :return:
    """
    # Build RAiD Handle URI
    raid_uri = 'https://api.raid.org.au/v1/handle/{}/redirect?demo={}'.format(
        urllib.quote(queue_record['handle'], safe=''), environment == 'demo'
    )

    orcid_request_object = {
        'title': {
            'title': {
                'value': 'RAiD ({})'.format(queue_record['handle'])
            },
            'subtitle': queue_record['role'],
            'translated-title': None
        },
        'short-description': queue_record['description'],
        'type': 'OTHER',
        'external-ids': {
            'external-id': [{
                'external-id-type': 'handle',
                'external-id-value': queue_record['handle'],
                'external-id-url': {
                    'value': raid_uri
                },
                'external-id-relationship': 'SELF'
            }]
        }
    }

    return orcid_request_object

