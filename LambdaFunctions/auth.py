"""
Authentication AWS Lambda handler code

Perform validation and redirection on custom authentication from third party
provided JWT.
"""
from __future__ import print_function

import os
import json
import base64
import urlparse
import re
import datetime
import jwt

INSTITUTION_SUBJECT = "RAiD:Institution"
PROVIDER_SUBJECT = "RAiD:Provider"


def jwt_self_encode(jwt_secret, jwt_audience, jwt_issuer_self, subject, organisation, months=6):
    """
    Generate a JWT token for an organisation that will last a number months of months after the current date.
    """
    future_date = datetime.date.today() + datetime.timedelta(months*365/12)
    payload = {
        'sub': subject,
        'aud': jwt_audience,
        'iss': jwt_issuer_self,
        'iat': datetime.datetime.now(),
        'exp': datetime.datetime.combine(future_date, datetime.time.min),
        'o': organisation
    }
    token = jwt.encode(payload, jwt_secret)
    return token
    

def jwt_validate(jwt_token, jwt_secret, jwt_audience, jwt_issuer_3rd_party, jwt_issuer_self):
    """
    Validate authenticity and validity of JWT token against authorised third party or self signed .
    Client should handle invalid token by sending a 401 Unauthorized response.
    """
    print("JWT token: " + jwt_token)
    try:
        # Identify token issuer and attributes
        decoded_base64_attributes = base64.b64decode(jwt_token.split('.')[1])
        attributes_obj = json.loads(decoded_base64_attributes)
        
        if attributes_obj["iss"] == jwt_issuer_3rd_party:
            # Authorized 3rd party
            return jwt.decode(jwt_token, jwt_secret, issuer=jwt_issuer_3rd_party, audience=jwt_audience,
                              options={'verify_exp': False})
        else:
            # Self Signed
            return jwt.decode(jwt_token, jwt_secret, issuer=jwt_issuer_self, audience=jwt_audience)

    except jwt.ExpiredSignatureError:
        # Signature has expired
        print("JWT Signature has expired")
        raise Exception('Unauthorized: JWT Signature has expired')
    except jwt.InvalidIssuerError:
        # Invalid Issuer
        print("JWT Invalid Issuer")
        raise Exception('Unauthorized: JWT Invalid Issuer')
    except jwt.InvalidAudienceError:
        # Invalid audience
        print("JWT Invalid audience")
        raise Exception('Unauthorized: JWT Invalid audience')
    except jwt.InvalidIssuedAtError:
        # Invalid audience
        print("JWT InvalidIssuedAtError")
        raise Exception('Unauthorized: JWT InvalidIssuedAtError')
    except:
        print("JWT Unexpected error")
        raise Exception('Unauthorized: JWT Unexpected error')


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
    decoded = jwt_validate(jwt_token, os.environ['JWT_SECRET'], os.environ['JWT_AUDIENCE'],
                           os.environ['JWT_ISSUER_3RD_PARTY'], os.environ['JWT_ISSUER_SELF'])
    print(json.dumps(decoded))

    # Generate Cookie string
    cookie_string = 'jwt_token={0}; domain={1}; Path=/;'.format(jwt_token, os.environ['SITE_DOMAIN'])

    return {
        'location': os.environ['SITE_URL'],
        'cookie': cookie_string
    }


def jwt_validation_handler(event, context):
    """
    Perform validation of API Gateway custom authoriser by checking JWT user token
    from cookie.
    """
    print("Client token: " + event['authorizationToken'])
    print("Method ARN: " + event['methodArn'])

    # Validate the incoming JWT token from pass Auth header
    jwt_token = event["authorizationToken"]

    decoded = jwt_validate(jwt_token, os.environ['JWT_SECRET'], os.environ['JWT_AUDIENCE'],
                           os.environ['JWT_ISSUER_3RD_PARTY'], os.environ['JWT_ISSUER_SELF'])

    if decoded["iss"] == os.environ['JWT_ISSUER_3RD_PARTY']:
        # User email will be Principal ID to be associated with calls. Ex 'user|j.smith@example.com'
        principal_id = 'user|' + decoded["https://aaf.edu.au/attributes"]["mail"]
    else:
        # Organisation is the principal ID
        principal_id = 'user|' + decoded["o"]

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

    policy = AuthPolicy(principal_id, aws_account_id)
    policy.restApiId = api_gateway_arn_tmp[0]
    policy.region = tmp[3]
    policy.stage = api_gateway_arn_tmp[1]

    if decoded["iss"] == os.environ['JWT_ISSUER_3RD_PARTY']:
        # Third party users only have permission to view activities
        policy.allow_method(HttpVerb.GET, '/activity/*')

        # Insert AAF member information to context
        context = {
            'mail': decoded["https://aaf.edu.au/attributes"]["mail"],
            'auEduPersonSharedToken': decoded["https://aaf.edu.au/attributes"]["auEduPersonSharedToken"],
            'displayname': decoded["https://aaf.edu.au/attributes"]["displayname"]
        }

    elif decoded["iss"] == os.environ['JWT_ISSUER_SELF'] and decoded["sub"] == PROVIDER_SUBJECT:
        # Self signed provider users can use all HTTP methods
        policy.allow_all_methods()
        context = {
            'o': decoded["organisation"]
        }

    elif decoded["iss"] == os.environ['JWT_ISSUER_SELF'] and decoded["sub"] == INSTITUTION_SUBJECT:
        # Self signed institution can only view activities
        policy.allow_method(HttpVerb.GET, '/activity/*')
        context = {
            'o': decoded["organisation"]
        }

    else:
        raise Exception('Unauthorized')

    # Finally, build the policy
    auth_response = policy.build()
    auth_response['context'] = context
    return auth_response


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

    def __init__(self, principal, aws_account_id):
        self.awsAccountId = aws_account_id
        self.principalId = principal
        self.allowMethods = []
        self.denyMethods = []

    def _add_method(self, effect, verb, resource, conditions):
        """
        Adds a method to the internal lists of allowed or denied methods. Each object in
        the internal list contains a resource ARN and a condition statement. The condition
        statement can be null.
        """
        if verb != '*' and not hasattr(HttpVerb, verb):
            raise NameError('Invalid HTTP verb ' + verb + '. Allowed verbs in HttpVerb class')
        resource_pattern = re.compile(self.pathRegex)
        if not resource_pattern.match(resource):
            raise NameError('Invalid resource path: ' + resource + '. Path should match ' + self.pathRegex)

        if resource[:1] == '/':
            resource = resource[1:]

        resource_arn = 'arn:aws:execute-api:{}:{}:{}/{}/{}/{}'.format(self.region, self.awsAccountId, self.restApiId,
                                                                      self.stage, verb, resource)

        if effect.lower() == 'allow':
            self.allowMethods.append({
                'resource_arn': resource_arn,
                'conditions': conditions
            })
        elif effect.lower() == 'deny':
            self.denyMethods.append({
                'resource_arn': resource_arn,
                'conditions': conditions
            })

    def _get_empty_statement(self, effect):
        """
        Returns an empty statement object prepopulated with the correct action and the
        desired effect.
        """
        statement = {
            'Action': 'execute-api:Invoke',
            'Effect': effect[:1].upper() + effect[1:].lower(),
            'Resource': []
        }

        return statement

    def _get_statement_for_effect(self, effect, methods):
        """
        This function loops over an array of objects containing a resourceArn and
        conditions statement and generates the array of statements for the policy.
        """
        statements = []

        if len(methods) > 0:
            statement = self._get_empty_statement(effect)

            for curMethod in methods:
                if curMethod['conditions'] is None or len(curMethod['conditions']) == 0:
                    statement['Resource'].append(curMethod['resourceArn'])
                else:
                    conditional_statement = self._get_empty_statement(effect)
                    conditional_statement['Resource'].append(curMethod['resourceArn'])
                    conditional_statement['Condition'] = curMethod['conditions']
                    statements.append(conditional_statement)

            if statement['Resource']:
                statements.append(statement)

        return statements

    def allow_all_methods(self):
        """
        Adds a '*' allow to the policy to authorize access to all methods of an API
        """
        self._add_method('Allow', HttpVerb.ALL, '*', [])

    def deny_all_methods(self):
        """
        Adds a '*' allow to the policy to deny access to all methods of an API
        """
        self._add_method('Deny', HttpVerb.ALL, '*', [])

    def allow_method(self, verb, resource):
        """
        Adds an API Gateway method (Http verb + Resource path) to the list of allowed
        methods for the policy
        """
        self._add_method('Allow', verb, resource, [])

    def deny_method(self, verb, resource):
        """
        Adds an API Gateway method (Http verb + Resource path) to the list of denied
        methods for the policy'
        """
        self._add_method('Deny', verb, resource, [])

    def allow_method_with_conditions(self, verb, resource, conditions):
        """
        Adds an API Gateway method (Http verb + Resource path) to the list of allowed
        methods and includes a condition for the policy statement. More on AWS policy
        conditions here: http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html#Condition
        """
        self._add_method('Allow', verb, resource, conditions)

    def deny_method_with_conditions(self, verb, resource, conditions):
        """
        Adds an API Gateway method (Http verb + Resource path) to the list of denied
        methods and includes a condition for the policy statement. More on AWS policy
        conditions here: http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html#Condition
        """
        self._add_method('Deny', verb, resource, conditions)

    def build(self):
        """
        Generates the policy document based on the internal lists of allowed and denied
        conditions. This will generate a policy with two main statements for the effect:
        one statement for Allow and one statement for Deny.
        Methods that includes conditions will have their own statement in the policy.
        """
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

        policy['policyDocument']['Statement'].extend(self._get_statement_for_effect('Allow', self.allowMethods))
        policy['policyDocument']['Statement'].extend(self._get_statement_for_effect('Deny', self.denyMethods))

        return policy
