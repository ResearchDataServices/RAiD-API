import os
import sys
import logging
import datetime
import json
import base64
import boto3
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


def generate_table_list_response(event, query_parameters, table, replacement_dictionary=None):
    """
    A generic method for Dynamo DB queries that return a list of items.
    :param event: Dictionary of values provided from the invoking API Gateway
    :param query_parameters: Dictionary of DynamoDB parameters unique to the calling method
    :param table: String representing the name of the DynamoDB table
    :param replacement_dictionary: Dictionary of new key names to replace current DyanmoDB name
    :return:
    """
    try:
        # Initialise DynamoDB
        dynamo_db = boto3.resource('dynamodb')
        dynamo_db_table = dynamo_db.Table(table)

        # Interpret and validate request body for optional parameters
        if event["queryStringParameters"]:
            try:
                parameters = event["queryStringParameters"]
                if "limit" in parameters:
                    query_parameters["Limit"] = int(parameters["limit"])
                if "ascending" in parameters and \
                        (parameters["ascending"] == 'False' or parameters["ascending"] == 'false'):
                    query_parameters["ScanIndexForward"] = False
                if "exclusiveStartKey" in parameters:
                    query_parameters["ExclusiveStartKey"] = json.loads(base64.urlsafe_b64decode(
                        parameters["exclusiveStartKey"].encode("ascii")
                    ))
            except ValueError as e:
                logger.error('Incorrect parameter type formatting: {}'.format(e))
                return generate_web_body_response('400', {'message': "Incorrect parameter type formatting."}, event)

        # Query table using parameters given and built to return a list of RAiDs the owner is attached too
        query_response = dynamo_db_table.query(**query_parameters)

        # Build response body
        return_body = {
            'items': query_response["Items"],
            'count': query_response["Count"],
            'scannedCount': query_response["ScannedCount"]
        }

        # Rename key name values to new name
        if replacement_dictionary:
            # Iterate over items and their contents
            for item in query_response["Items"]:
                for key, value in item.items():
                    if key in replacement_dictionary:
                        # Remove the original key/value pair and replace with the new key name
                        item[replacement_dictionary[key]] = item.pop(key)

        if 'LastEvaluatedKey' in query_response:
            return_body['lastEvaluatedKey'] = base64.urlsafe_b64encode(json.dumps(query_response["LastEvaluatedKey"]))

        return generate_web_body_response('200', return_body, event)

    except:
        logger.error('Unable to generate a DynamoDB list response: {}'.format(sys.exc_info()[0]))
        return generate_web_body_response('500',
                                          {'message': "Unable to perform request due to error. Please check structure"
                                                      " of the parameters."},
                                          event)
