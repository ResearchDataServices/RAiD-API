import os
import json
import urlparse
import sys
import logging
import boto3
import auth
from helpers import web_helpers


# Set Logging Level
logger = logging.getLogger()
logger.setLevel(logging.ERROR)


def jwt_redirection_handler(event, context):
    """
    Perform validation and redirection for a SAML assertion endpoint.
    Parse url encoded form data for JWT token and check against secret.
    """
    # Parse form data which should contain at minimum an SAML assertion
    body_parse = urlparse.parse_qs(event["body"])
    # Capture JWT token
    jwt_token = body_parse["assertion"][0]

    # Decode and validate JWT token
    decoded = auth.jwt_validate(jwt_token, os.environ['JWT_SECRET'], os.environ['JWT_AUDIENCE'],
                                os.environ['JWT_ISSUER_3RD_PARTY'], os.environ['JWT_ISSUER_SELF'])
    print(json.dumps(decoded))

    # Generate Cookie string
    cookie_string = 'jwt_token={0}; domain={1}; Path=/;'.format(jwt_token, os.environ['SITE_DOMAIN'])

    return {
        'location': os.environ['SITE_URL'],
        'cookie': cookie_string
    }


def custom_authorisation_handler(event, context):
    """
    Perform validation of API Gateway custom authoriser by checking JWT user token
    from header.
    """
    print("Client token: " + event['authorizationToken'])
    print("Method ARN: " + event['methodArn'])

    # Validate the incoming JWT token from pass Auth header
    authentication_token = event["authorizationToken"]
    jwt_token = authentication_token.replace(auth.AUTHENTICATION_SCHEME, '').strip(' ')

    decoded = auth.jwt_validate(jwt_token, os.environ['JWT_SECRET'], os.environ['JWT_AUDIENCE'],
                                os.environ['JWT_ISSUER_3RD_PARTY'], os.environ['JWT_ISSUER_SELF'])

    if decoded["iss"] == os.environ['JWT_ISSUER_3RD_PARTY']:
        # User email will be Principal ID to be associated with calls. Ex 'user|j.smith@example.com'
        principal_id = 'user|' + decoded["https://aaf.edu.au/attributes"]["mail"]
    else:
        # Organisation is the principal ID
        principal_id = decoded["sub"]

    '''
    If the token is valid, a policy must be generated which will allow or deny
    access to the client. If access is denied, the client will receive a 403
    Access Denied response. If access is allowed, API Gateway will proceed with
    the backend integration configured on the method that was called.

    The policy is cached for 5 minutes by default (TTL is
    configurable in the authorizer) and will apply to subsequent calls to any
    method/resource in the RestApi made with the same token.
    '''
    tmp = event['methodArn'].split(':')
    api_gateway_arn_tmp = tmp[5].split('/')
    aws_account_id = tmp[4]

    policy = auth.AuthPolicy(principal_id, aws_account_id)
    policy.restApiId = api_gateway_arn_tmp[0]
    policy.region = tmp[3]
    policy.stage = api_gateway_arn_tmp[1]

    if decoded["iss"] == os.environ['JWT_ISSUER_SELF'] and decoded["role"] == os.environ['PROVIDER_ROLE']:
        # Self signed provider users can use all HTTP methods
        policy.allow_all_methods()
        context = {
            'provider': decoded["sub"],
            'role': decoded["role"],
        }

        if "environment" in decoded:
            context["environment"] = decoded["environment"]
        else:
            context["environment"] = "demo"

    elif decoded["iss"] == os.environ['JWT_ISSUER_SELF'] and decoded["role"] == os.environ['INSTITUTION_ROLE']:
        policy.allow_method(auth.HttpVerb.GET, '/*')
        policy.allow_method(auth.HttpVerb.GET, '/RAiD/*')
        policy.allow_method(auth.HttpVerb.GET, '/provider/*')
        policy.allow_method(auth.HttpVerb.ALL, '/institution/*')
        context = {
            'provider': decoded["sub"],
            'grid': decoded["grid"],
            'role': decoded["role"],
        }

        if "environment" in decoded:
            context["environment"] = decoded["environment"]
        else:
            context["environment"] = "demo"

    else:
        raise Exception('Unauthorized')

    # Finally, build the policy
    auth_response = policy.build()
    auth_response['context'] = context
    return auth_response


def authenticate_token_handler(event, context):
    """
    Validate a JWT token and provide a descriptive human readable bodied 200
    response or a 401 unauthorised response.
    :param event:
    :param context:
    :return:
    """
    try:
        # Validate the incoming JWT token from passed in the body
        body = json.loads(event["body"])
        jwt_token = body["token"]

        decoded_token = auth.jwt_validate(jwt_token, os.environ['JWT_SECRET'], os.environ['JWT_AUDIENCE'],
                                          os.environ['JWT_ISSUER_3RD_PARTY'], os.environ['JWT_ISSUER_SELF'])

        return web_helpers.generate_web_body_response('200', decoded_token, event)

    except Exception, e:
        if 'Unauthorized:' in str(e):
            return web_helpers.generate_web_body_response('401', str(e), event)

        logger.error('Unable to authenticate token: {}'.format(sys.exc_info()[0]))
        return web_helpers.generate_web_body_response(
            '400',
            {
                'message': "Unable to authenticate the token. Please check structure of the body."
            },
            event
        )

