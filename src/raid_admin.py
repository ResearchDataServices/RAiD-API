from __future__ import print_function

import os
import sys
import json
import logging
import datetime
import jwt
import base64
import urllib
import boto3
from boto3.dynamodb.conditions import Key, Attr

# Roles
INSTITUTION_ROLE = "institution"
SERVICE_ROLE = "service"

# Token issuing
JWT_ISSUER = os.environ["JWT_ISSUER"]
JWT_AUDIENCE = os.environ["JWT_AUDIENCE"]
JWT_SECRET = os.environ["JWT_SECRET"]

# Set Logging Level
logger = logging.getLogger()
logger.setLevel(logging.ERROR)


def generate_web_body_response(status_code, body):
    """
    Generate a valid API Gateway CORS enabled JSON body response
    :param status_code: string of a HTTP status code
    :param body: Dictionary object, converted to JSON
    :return:
    """
    return {
        'statusCode': status_code,
        "headers": {
            "Access-Control-Allow-Headers": "Content-Type,Authorization,X-Amz-Date,X-Api-Key,X-Amz-Security-Token",
            "Access-Control-Allow-Methods": "DELETE,GET,HEAD,OPTIONS,PATCH,POST,PUT",
            "Access-Control-Allow-Origin": "*"
        },
        'body': json.dumps(body)
    }


def jwt_role_encode(jwt_secret, jwt_audience, jwt_issuer, subject, role, environment, months=6):
    """
    Generate a JWT token for a subject that will last a number months of months after the current date.
    :param jwt_secret: String used for encrypted JWT signature 
    :param jwt_audience: Target site the JWT token will be authenticated against
    :param jwt_issuer: Organisation name of the principal issuer
    :param subject: Identifying attribute for the JWT token subject 
    :param role: Must be either 'service' or 'role'
    :param months: Number of months the token should expire from the current date
    :param environment: The environment (demo or live) of RAiD
    :return: JWT Token
    """
    try:
        # Validate role type
        if role != INSTITUTION_ROLE and role != SERVICE_ROLE:
            raise Exception('Invalid RAiD JWT role type: {}'.format(role))

        # Calculate future expiration date
        future_date = datetime.date.today() + datetime.timedelta(months*365/12)

        # Generate payload and token
        payload = {
            'sub': subject,
            'aud': jwt_audience,
            'iss': jwt_issuer,
            'iat': datetime.datetime.now(),
            'exp': datetime.datetime.combine(future_date, datetime.time.min),
            'environment': environment,
            'role': role
        }
        token = jwt.encode(payload, jwt_secret)
        return token
    except:
        logger.error("JWT encoding error: {}".format(sys.exc_info()[0]))
        raise


def institution_crud_handler(event, context):
    """
    CRUD handler for institutions table
    :param event: 
    :param context: 
    :return: 
    """
    try:
        logger.info('Institution CRUD Event={}'.format(event))

        # validate event
        if "query" not in event or "parameters" not in event:
            raise Exception("Event must contain the institution 'query' and 'parameters'.")

        # Initialise DynamoDB
        dynamodb = boto3.resource('dynamodb')
        institution_table = dynamodb.Table(os.environ["INSTITUTION_TABLE"])

        # Create new item
        if event["query"] == "create":
            # Validate parameter existence
            if "name" not in event["parameters"] or "grid" not in event["parameters"]:
                raise Exception("'name' and 'grid' must be provided in 'parameters to generate a JWT token.")

            # TODO regex validate grid id 'grid.[NUMERIC].[ALPHANUMERIC]'

            # Get current datetime
            now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Get environment
            if "environment" in event["parameters"]:
                environment = event["parameters"]["environment"]
            else:
                environment = "demo"

            # Create JWT token
            jwt = jwt_role_encode(JWT_SECRET, JWT_AUDIENCE, JWT_ISSUER, event["parameters"]["grid"], INSTITUTION_ROLE,
                                  environment, 24)

            # Define item
            item = {
                    'Name': event["parameters"]["name"],
                    'Grid': event["parameters"]["grid"],
                    'Date': now,
                    'Token': jwt
            }

            # Send Dynamo DB put response
            institution_table.put_item(Item=item)

            return item

        # Use existing item
        elif event["query"] == "update" or event["query"] == "read" or event["query"] == "delete":
            # Validate required item key values
            if "grid" not in event["parameters"] or "date" not in event["parameters"]:
                raise Exception("Key fields 'grid' and 'date' must be provided in 'parameters' for this query.")

            if event["query"] == "update":
                # Get environment
                if "environment" in event["parameters"]:
                    environment = event["parameters"]["environment"]
                else:
                    environment = "demo"

                update_response = institution_table.update_item(
                    Key={
                        'Grid': event["parameters"]["grid"],
                        'Date': event["parameters"]["date"]
                    },
                    UpdateExpression="set #token = :t",
                    ExpressionAttributeValues={
                        ':t': jwt_role_encode(JWT_SECRET, JWT_AUDIENCE, JWT_ISSUER, event["parameters"]["grid"],
                                              INSTITUTION_ROLE, environment, 24)
                    },
                    ExpressionAttributeNames={
                        '#token': "Token",
                    },
                    ReturnValues="UPDATED_NEW"
                )

                return update_response["Attributes"]

            elif event["query"] == "read":
                read_response = institution_table.get_item(
                    Key={
                        'Grid': event["parameters"]["grid"],
                        'Date': event["parameters"]["date"]
                    }
                )

                if "Item" not in read_response:
                    raise Exception("No item found matching provided keys.")

                return read_response["Item"]

            elif event["query"] == "delete":
                if "grid" not in event["parameters"] or "date" not in event["parameters"]:
                    raise Exception("'grid' and 'date' must be provided in 'parameters to generate a new JWT token.")

                delete_response = institution_table.delete_item(
                    Key={
                        'Grid': event["parameters"]["grid"],
                        'Date': event["parameters"]["date"]
                    }
                )

        elif event["query"] == "list":
            if "grid" not in event["parameters"]:
                raise Exception("Key fields 'grid' must be provided in 'parameters' for this query.")

            list_response = institution_table.query(
                KeyConditionExpression=Key('Grid').eq(event["parameters"]["grid"])
            )

            # TODO ExclusiveStartKey

            return list_response

        elif event["query"] == "scan":
            if "name" in event["parameters"]:  # Filter by name
                fe = Attr("Name").contains(event["parameters"]["name"])
                pe = "Grid, #d, #n, #t"
                ean = {"#d": "Date", "#n": "Name", "#t": "Token"}

                list_response = institution_table.scan(
                    FilterExpression=fe,
                    ProjectionExpression=pe,
                    ExpressionAttributeNames=ean
                )

                # TODO ExclusiveStartKey

            else:
                list_response = institution_table.scan()  # Scan without filer

                # TODO ExclusiveStartKey

            return list_response

        else:
            raise Exception("Invalid query type '{}'."
                            " Only 'create', 'update', 'read', 'delete', 'list', and 'scan' may be used.".format(event["query"]))
    except:
        logger.error('Unexpected error: {}'.format(sys.exc_info()[0]))
        raise


def service_crud_handler(event, context):
    """
    CRUD handler for service table
    :param event:
    :param context:
    :return:
    """
    try:
        logger.info('Service CRUD Event={}'.format(event))

        # validate event
        if "query" not in event or "parameters" not in event:
            raise Exception("Event must contain the service 'query' and 'parameters'.")

        # Initialise DynamoDB
        dynamodb = boto3.resource('dynamodb')
        service_table = dynamodb.Table(os.environ["SERVICE_TABLE"])

        # Create new item
        if event["query"] == "create":
            # Validate parameter existence
            if "name" not in event["parameters"]:
                raise Exception("'name' must be provided in 'parameters to generate a JWT token.")

            # Get current datetime
            now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Get environment
            if "environment" in event["parameters"]:
                environment = event["parameters"]["environment"]
            else:
                environment = "demo"

            # Create JWT token
            jwt = jwt_role_encode(JWT_SECRET, JWT_AUDIENCE, JWT_ISSUER, event["parameters"]["name"], SERVICE_ROLE,
                                  environment, 24)

            # Define item
            item = {
                    'Name': event["parameters"]["name"],
                    'Date': now,
                    'Token': jwt
            }

            # Send Dynamo DB put response
            service_table.put_item(Item=item)

            return item

        # Use existing item
        elif event["query"] == "update" or event["query"] == "read" or event["query"] == "delete":
            # Validate required item key values
            if "name" not in event["parameters"] or "date" not in event["parameters"]:
                raise Exception("Key fields 'name' and 'date' must be provided in 'parameters' for this query.")

            if event["query"] == "update":
                # Get environment
                if "environment" in event["parameters"]:
                    environment = event["parameters"]["environment"]
                else:
                    environment = "demo"

                update_response = service_table.update_item(
                    Key={
                        'Name': event["parameters"]["name"],
                        'Date': event["parameters"]["date"]
                    },
                    UpdateExpression="set #token = :t",
                    ExpressionAttributeValues={
                        ':t': jwt_role_encode(JWT_SECRET, JWT_AUDIENCE, JWT_ISSUER, event["parameters"]["name"],
                                              SERVICE_ROLE, environment, 24)
                    },
                    ExpressionAttributeNames={
                        '#token': "Token",
                    },
                    ReturnValues="UPDATED_NEW"
                )

                return update_response["Attributes"]

            elif event["query"] == "read":
                read_response = service_table.get_item(
                    Key={
                        'Name': event["parameters"]["name"],
                        'Date': event["parameters"]["date"]
                    }
                )

                if "Item" not in read_response:
                    raise Exception("No item found matching provided keys.")

                return read_response["Item"]

            elif event["query"] == "delete":
                if "name" not in event["parameters"] or "date" not in event["parameters"]:
                    raise Exception("'name' and 'date' must be provided in 'parameters to generate a new JWT token.")

                delete_response = service_table.delete_item(
                    Key={
                        'Name': event["parameters"]["name"],
                        'Date': event["parameters"]["date"]
                    }
                )

        elif event["query"] == "list":
            if "name" not in event["parameters"]:
                raise Exception("Key fields 'name' must be provided in 'parameters' for this query.")

            list_response = service_table.query(
                KeyConditionExpression=Key('Name').eq(event["parameters"]["name"])
            )

            # TODO ExclusiveStartKey

            return list_response

        elif event["query"] == "scan":
            if "name" in event["parameters"]:  # Filter by name
                fe = Attr("Name").contains(event["parameters"]["name"])
                pe = "#d, #n, #t"
                ean = {"#d": "Date", "#n": "Name", "#t": "Token"}

                list_response = service_table.scan(
                    FilterExpression=fe,
                    ProjectionExpression=pe,
                    ExpressionAttributeNames=ean
                )

                # TODO ExclusiveStartKey

            else:
                list_response = service_table.scan()  # Scan without filer

                # TODO ExclusiveStartKey

            return list_response

        else:
            raise Exception("Invalid query type '{}'."
                            " Only 'create', 'update', 'read', 'delete', 'list', and 'scan' may be used.".format(event["query"]))
    except:
        logger.error('Unexpected error: {}'.format(sys.exc_info()[0]))
        raise


def create_provider_key_handler(event, context):
    try:
        # Interpret and validate request body
        body = json.loads(event["body"])

        if "name" not in body:
            raise Exception("'name' must be provided in 'parameters to generate a JWT token.")

        # Get current datetime
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Get environment
        if "environment" in body:
            environment = body["environment"]
        else:
            environment = "demo"

        # Create JWT token
        jwt = jwt_role_encode(JWT_SECRET, JWT_AUDIENCE, JWT_ISSUER, body["name"], SERVICE_ROLE, environment, 24)

        # Define item
        item = {'Name': body["name"], 'Date': now, 'Token': jwt, 'environment': environment}

        # Initialise DynamoDB
        dynamodb = boto3.resource('dynamodb')
        provider_table = dynamodb.Table(os.environ["PROVIDER_TABLE"])
        # Send Dynamo DB put response
        provider_table.put_item(Item=item)

        return generate_web_body_response('200', item)

    except:
        logger.error('Unexpected error: {}'.format(sys.exc_info()[0]))
        return generate_web_body_response('400', {'message': "Unable to create a Provider token. "
                                                             "'name' must be provided in the body of the request"})


def delete_provider_key_handler(event, context):
    try:
        name = urllib.unquote(urllib.unquote(event["pathParameters"]["provider"]))

    except:
        logger.error('Unable to validate provider name: {}'.format(sys.exc_info()[0]))
        return generate_web_body_response(
            '400',
            {'message': "Incorrect path parameter formatting for provider name. Ensure it is a URL encoded string."}
        )

    try:
        # Interpret and validate request body
        body = json.loads(event["body"])

        if "date" not in body:
            raise Exception("A valid 'date' must be provided in parameters to delete the JWT token.")

        # Initialise DynamoDB
        dynamodb = boto3.resource('dynamodb')
        provider_table = dynamodb.Table(os.environ["PROVIDER_TABLE"])
        provider_table.delete_item(Key={'Name': name, 'Date': body["date"]})
        return generate_web_body_response('200', {'message': "Successfully deleted provider token."})

    except:
        logger.error('Unexpected error: {}'.format(sys.exc_info()[0]))
        return generate_web_body_response(
            '400',
            {'message': "A valid 'date' must be provided in parameters to delete the JWT token."}
        )


def get_provider_keys_handler(event, context):
    try:
        name = urllib.unquote(urllib.unquote(event["pathParameters"]["provider"]))

        query_parameters = {'KeyConditionExpression': Key('Name').eq(name)}

        return generate_table_list_response(event, query_parameters, os.environ["PROVIDER_TABLE"])

    except:
        logger.error('Unable to validate provider name: {}'.format(sys.exc_info()[0]))
        return generate_web_body_response(
            '400',
            {'message': "Incorrect path parameter type formatting for provider name. Ensure it is a URL encoded string"}
        )


def create_provider_metadata_handler(event, context):
    try:
        # Interpret and validate request body
        body = json.loads(event["body"])

        if "name" not in body:
            raise Exception("'name' must be provided in 'parameters to generate a JWT token.")

        # Define item
        item = {'name': body["name"]}

        if 'isni' in body:
            item['isni'] = body['isni']

        if 'grid' in body:
            item['grid'] = body['grid']

        # Initialise DynamoDB
        dynamodb = boto3.resource('dynamodb')
        provider_table = dynamodb.Table(os.environ["PROVIDER_METADATA_TABLE"])

        # Send Dynamo DB put response
        provider_table.put_item(Item=item)
        return generate_web_body_response('200', item)

    except:
        logger.error('Unexpected error: {}'.format(sys.exc_info()[0]))
        return generate_web_body_response(
            '400',
            {'message': "Incorrect path parameter type formatting for provider name. Ensure it is a URL encoded string"}
        )


def update_provider_metadata_handler(event, context):
    try:
        name = urllib.unquote(urllib.unquote(event["pathParameters"]["provider"]))

    except:
        logger.error('Unable to validate provider name: {}'.format(sys.exc_info()[0]))
        return generate_web_body_response(
            '400',
            {'message': "Incorrect path parameter type formatting for provider name. Ensure it is a URL encoded string"}
        )

    try:
        # Interpret and validate request body
        body = json.loads(event["body"])

        if 'isni' not in body or 'grid' not in body:
            raise Exception("'isni' and 'grid' must be provided.")

        dynamodb = boto3.resource('dynamodb')
        provider_table = dynamodb.Table(os.environ["PROVIDER_METADATA_TABLE"])

        # Update meta values
        update_response = provider_table.update_item(
            Key={'name': name},
            UpdateExpression="set isni = :i, grid = :g",
            ExpressionAttributeValues={
                ':i': body['isni'],
                ':g': body['grid']
            },
            ReturnValues="ALL_NEW"
        )

        return generate_web_body_response('200', update_response["Attributes"])

    except:
        logger.error('Unexpected error: {}'.format(sys.exc_info()[0]))
        return generate_web_body_response(
            '400',
            {'message': "Incorrect path parameter formatting for provider name. Ensure it is a URL encoded string."}
        )


def delete_provider_metadata_handler(event, context):
    try:
        name = urllib.unquote(urllib.unquote(event["pathParameters"]["provider"]))

    except:
        logger.error('Unable to validate provider name: {}'.format(sys.exc_info()[0]))
        return generate_web_body_response(
            '400',
            {'message': "Incorrect path parameter type formatting for provider name. Ensure it is a URL encoded string"}
        )

    try:
        dynamodb = boto3.resource('dynamodb')
        provider_table = dynamodb.Table(os.environ["PROVIDER_METADATA_TABLE"])
        provider_table.delete_item(Key={'name': name})
        return generate_web_body_response('200', {'message': "Successfully deleted provider."})

    except:
        logger.error('Unexpected error: {}'.format(sys.exc_info()[0]))
        return generate_web_body_response(
            '400',
            {'message': "Incorrect path parameter formatting for provider name. Ensure it is a URL encoded string."}
        )


def get_provider_metadata_handler(event, context):
    try:
        name = urllib.unquote(urllib.unquote(event["pathParameters"]["provider"]))

        # Initialise DynamoDB
        dynamo_db = boto3.resource('dynamodb')
        provider_table = dynamo_db.Table(os.environ["PROVIDER_METADATA_TABLE"])

        # Check if provider meta data exists
        query_response = provider_table.query(KeyConditionExpression=Key('name').eq(name))

        if query_response["Count"] != 1:
            return generate_web_body_response('404', {'message': "Provider '{}' has no meta data.".format(name)})

        # Assign raid item to single item, since the result will be an array of one item
        provider_metadata = query_response['Items'][0]

        return generate_web_body_response('200', provider_metadata)


    except:
        logger.error('Unable to validate provider name: {}'.format(sys.exc_info()[0]))
        return generate_web_body_response(
            '400',
            {'message': "Incorrect path parameter formatting for provider name. Ensure it is a URL encoded string."}
        )


def generate_table_list_response(event, query_parameters, table):
    """
    A generic method for Dynamo DB queries that return a list of items.
    :param event: Dictionary of values provided from the invoking API Gateway
    :param query_parameters: Dictionary of DynamoDB parameters unique to the calling method
    :param table: String representing the name of the DynamoDB table
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
                return generate_web_body_response('400', {'message': "Incorrect parameter type formatting."})

        # Query table using parameters given and built to return a list of RAiDs the owner is attached too
        query_response = dynamo_db_table.query(**query_parameters)

        # Build response body
        return_body = {
            'items': query_response["Items"],
            'count': query_response["Count"],
            'scannedCount': query_response["ScannedCount"]
        }

        if 'LastEvaluatedKey' in query_response:
            return_body['lastEvaluatedKey'] = base64.urlsafe_b64encode(json.dumps(query_response["LastEvaluatedKey"]))

        return generate_web_body_response('200', return_body)

    except:
        logger.error('Unable to generate a DynamoDB list response: {}'.format(sys.exc_info()[0]))
        return generate_web_body_response('500', {'message': "Unable to perform request due to error. "
                                                             "Please check structure of the parameters."})

