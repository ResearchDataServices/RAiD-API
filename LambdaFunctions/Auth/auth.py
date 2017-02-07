'''
Authentication AWS Lambda handler code

Perform validation and redirection on custom authentication from third party
provided JWT.

'''
from __future__ import print_function

import os
import json
import urlparse
import re
import boto3
import jwt

from boto3.dynamodb.conditions import Key
from boto3.session import Session

JWT_SECRET =  os.environ['JWT_SECRET']
SITE_URL =  os.environ['SITE_URL']
SITE_DOMAIN =  os.environ['SITE_DOMAIN']
JWT_ISSUER =  os.environ['JWT_ISSUER']
JWT_AUDIENCE =  os.environ['JWT_AUDIENCE']

def jwt_validate(jwtToken):
    '''
    Validate authenticity and validity of JWT token.
    Client should handle invalid token by sending a 401 Unauthorized response.
    '''
    print("JWT token: " + jwtToken)
    try:
        decoded = jwt.decode(jwtToken, JWT_SECRET, issuer=JWT_ISSUER, audience=JWT_AUDIENCE)
        return decoded
    except jwt.ExpiredSignatureError:
        # Signature has expired
        print("JWT Signature has expired")
        raise Exception('Unauthorized')
    except jwt.InvalidIssuerError:
        # Invalid Issuer
        print("JWT Invalid Issuer")
        raise Exception('Unauthorized')
    except jwt.InvalidAudienceError:
        # Invalid audience
        print("JWT Invalid audience")
        raise Exception('Unauthorized')
    except jwt.InvalidIssuedAtError :
        # Invalid audience
        print("JWT InvalidIssuedAtError")
        raise Exception('Unauthorized')
    except:
        print("JWT Unexpected error")
        raise Exception('Unauthorized')
    
def jwt_redirection_handler(event, context):
    '''
    Perform validation and redirection for a SAML assertion endpoint. 
    Parse url encoded form data for JWT token and check against secret.
    '''
    #Parse form data which should contain at minimum an SAML assertion
    body_parse = urlparse.parse_qs(event["body"])
    
    #Capture JWT and validate
    jwtToken = body_parse["assertion"][0]
    decoded = jwt_validate(jwtToken)
    print(json.dumps(decoded))
    
    #Generate Cookie string
    cookie_string = 'jwtToken={0}; domain={1}; Path=/;'.format(jwtToken, SITE_DOMAIN)
    
    return {
        'location' : SITE_URL,
        'cookie': cookie_string
    }

def jwt_validation_handler(event, context):
    '''
    Perform validation of API Gateway custom authoriser by checking JWT user token
    from cookie.
    '''
    print("Client token: " + event['authorizationToken'])
    print("Method ARN: " + event['methodArn'])

    # Validate the incoming JWT token from pass Auth header
    jwtToken = event["authorizationToken"]
    
    decoded = jwt_validate(jwtToken)

    # User email will be Principal ID to be associated with calls. Ex 'user|j.smith@example.com'
    principalId = 'user|' + decoded["mail"]

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
    apiGatewayArnTmp = tmp[5].split('/')
    awsAccountId = tmp[4]

    policy = AuthPolicy(principalId, awsAccountId)
    policy.restApiId = apiGatewayArnTmp[0]
    policy.region = tmp[3]
    policy.stage = apiGatewayArnTmp[1]
   
    #Permit method usage. Ex policy.allowMethod(HttpVerb.GET, '/pets/*')
    policy.allowAllMethods()

    # Finally, build the policy
    authResponse = policy.build()

    '''
    Key-value pairs associated with the authenticated principal
    these are made available by APIGW like so: $context.authorizer.<key>
    additional context is cached. $context.authorizer.key -> value
    '''

    # Insert AAF member information
    context = {
        'mail': decoded["mail"] ,
        'edupersonsharedtoken': decoded["edupersonsharedtoken"],
        'displayname': decoded["displayname"]
    }

    authResponse['context'] = context

    return authResponse


class HttpVerb:
    GET = 'GET'
    POST = 'POST'
    PUT = 'PUT'
    PATCH = 'PATCH'
    HEAD = 'HEAD'
    DELETE = 'DELETE'
    OPTIONS = 'OPTIONS'
    ALL = '*'


class AuthPolicy(object):
    # The AWS account id the policy will be generated for. This is used to create the method ARNs.
    awsAccountId = ''
    # The principal used for the policy, this should be a unique identifier for the end user.
    principalId = ''
    # The policy version used for the evaluation. This should always be '2012-10-17'
    version = '2012-10-17'
    # The regular expression used to validate resource paths for the policy
    pathRegex = '^[/.a-zA-Z0-9-\*]+$'

    '''Internal lists of allowed and denied methods.

    These are lists of objects and each object has 2 properties: A resource
    ARN and a nullable conditions statement. The build method processes these
    lists and generates the approriate statements for the final policy.
    '''
    allowMethods = []
    denyMethods = []

    # The API Gateway API id. By default this is set to '*'
    restApiId = '*'
    # The region where the API is deployed. By default this is set to '*'
    region = '*'
    # The name of the stage used in the policy. By default this is set to '*'
    stage = '*'

    def __init__(self, principal, awsAccountId):
        self.awsAccountId = awsAccountId
        self.principalId = principal
        self.allowMethods = []
        self.denyMethods = []

    def _addMethod(self, effect, verb, resource, conditions):
        '''Adds a method to the internal lists of allowed or denied methods. Each object in
        the internal list contains a resource ARN and a condition statement. The condition
        statement can be null.'''
        if verb != '*' and not hasattr(HttpVerb, verb):
            raise NameError('Invalid HTTP verb ' + verb + '. Allowed verbs in HttpVerb class')
        resourcePattern = re.compile(self.pathRegex)
        if not resourcePattern.match(resource):
            raise NameError('Invalid resource path: ' + resource + '. Path should match ' + self.pathRegex)

        if resource[:1] == '/':
            resource = resource[1:]

        resourceArn = 'arn:aws:execute-api:{}:{}:{}/{}/{}/{}'.format(self.region, self.awsAccountId, self.restApiId, self.stage, verb, resource)

        if effect.lower() == 'allow':
            self.allowMethods.append({
                'resourceArn': resourceArn,
                'conditions': conditions
            })
        elif effect.lower() == 'deny':
            self.denyMethods.append({
                'resourceArn': resourceArn,
                'conditions': conditions
            })

    def _getEmptyStatement(self, effect):
        '''Returns an empty statement object prepopulated with the correct action and the
        desired effect.'''
        statement = {
            'Action': 'execute-api:Invoke',
            'Effect': effect[:1].upper() + effect[1:].lower(),
            'Resource': []
        }

        return statement

    def _getStatementForEffect(self, effect, methods):
        '''This function loops over an array of objects containing a resourceArn and
        conditions statement and generates the array of statements for the policy.'''
        statements = []

        if len(methods) > 0:
            statement = self._getEmptyStatement(effect)

            for curMethod in methods:
                if curMethod['conditions'] is None or len(curMethod['conditions']) == 0:
                    statement['Resource'].append(curMethod['resourceArn'])
                else:
                    conditionalStatement = self._getEmptyStatement(effect)
                    conditionalStatement['Resource'].append(curMethod['resourceArn'])
                    conditionalStatement['Condition'] = curMethod['conditions']
                    statements.append(conditionalStatement)

            if statement['Resource']:
                statements.append(statement)

        return statements

    def allowAllMethods(self):
        '''Adds a '*' allow to the policy to authorize access to all methods of an API'''
        self._addMethod('Allow', HttpVerb.ALL, '*', [])

    def denyAllMethods(self):
        '''Adds a '*' allow to the policy to deny access to all methods of an API'''
        self._addMethod('Deny', HttpVerb.ALL, '*', [])

    def allowMethod(self, verb, resource):
        '''Adds an API Gateway method (Http verb + Resource path) to the list of allowed
        methods for the policy'''
        self._addMethod('Allow', verb, resource, [])

    def denyMethod(self, verb, resource):
        '''Adds an API Gateway method (Http verb + Resource path) to the list of denied
        methods for the policy'''
        self._addMethod('Deny', verb, resource, [])

    def allowMethodWithConditions(self, verb, resource, conditions):
        '''Adds an API Gateway method (Http verb + Resource path) to the list of allowed
        methods and includes a condition for the policy statement. More on AWS policy
        conditions here: http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html#Condition'''
        self._addMethod('Allow', verb, resource, conditions)

    def denyMethodWithConditions(self, verb, resource, conditions):
        '''Adds an API Gateway method (Http verb + Resource path) to the list of denied
        methods and includes a condition for the policy statement. More on AWS policy
        conditions here: http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html#Condition'''
        self._addMethod('Deny', verb, resource, conditions)

    def build(self):
        '''Generates the policy document based on the internal lists of allowed and denied
        conditions. This will generate a policy with two main statements for the effect:
        one statement for Allow and one statement for Deny.
        Methods that includes conditions will have their own statement in the policy.'''
        if ((self.allowMethods is None or len(self.allowMethods) == 0) and
                (self.denyMethods is None or len(self.denyMethods) == 0)):
            raise NameError('No statements defined for the policy')

        policy = {
            'principalId': self.principalId,
            'policyDocument': {
                'Version': self.version,
                'Statement': []
            }
        }

        policy['policyDocument']['Statement'].extend(self._getStatementForEffect('Allow', self.allowMethods))
        policy['policyDocument']['Statement'].extend(self._getStatementForEffect('Deny', self.denyMethods))

        return policy
