import os
import sys
import logging
import datetime
import json
from boto.connection import AWSAuthConnection

# Set Logging Level
logger = logging.getLogger()
logger.setLevel(logging.ERROR)


class ESConnection(AWSAuthConnection):
    """
    Class used for ElasticSearch connection requests
    """
    def __init__(self, region, **kwargs):
        super(ESConnection, self).__init__(**kwargs)
        self._set_auth_region_name(region)
        self._set_auth_service_name('es')

    def _required_auth_capability(self):
        return ['hmac-v4']


def push_api_event_log(region, host, event):
    """
    Push API Gateway event to ElasticSearch
    :param region: AWS region ES service is in
    :param host: ES endpoint, <<path>>.ap-southeast-2.es.amazonaws.com
    :param event: API Gateway trigger event
    :return:
    """
    log_id = event["requestContext"]["requestId"]
    index_name = 'cwl-{}'.format(datetime.datetime.now().strftime("%Y.%m.%d"))
    iso_date = str(datetime.datetime.now().isoformat())

    action = {
        "index": {
            '_index': index_name,
            '_type': event["requestContext"]["apiId"],
            '_id': log_id
        }
    }

    source = {
        '@id': log_id,
        '@timestamp': iso_date,
        '@event': event,
    }

    log = '{}\n{}\n'.format(json.dumps(action), json.dumps(source))

    client = ESConnection(region=region, host=host, is_secure=False)
    resp = client.make_request(method='POST', path='/_bulk', data=log)

    return resp.read()


def generate_web_body_response(status_code, body, event=None):
    """
    Generate a valid API Gateway CORS enabled JSON body response
    :param status_code: string of a HTTP status code
    :param body: Dictionary object, converted to JSON
    :param event: API Gateway trigger event
    :return:
    """
    try:
        if event and "ELASTICSEARCH_HOST" in os.environ:
            event["httpStatus"] = status_code
            push_api_event_log(os.environ['AWS_REGION'], os.environ['ELASTICSEARCH_HOST'], event)
    except:
        logger.error('Unable to log to elastic search: {}'.format(sys.exc_info()[0]))

    return {
        'statusCode': status_code,
        "headers": {
            "Access-Control-Allow-Headers": "Content-Type,Authorization,X-Amz-Date,X-Api-Key,X-Amz-Security-Token",
            "Access-Control-Allow-Methods": "DELETE,GET,HEAD,OPTIONS,PATCH,POST,PUT",
            "Access-Control-Allow-Origin": "*"
        },
        'body': json.dumps(body)
    }
