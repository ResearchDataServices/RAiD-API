from __future__ import print_function

import sys
import logging
import datetime
import jwt

INSTITUTION_ROLE = "institution"
SERVICE_ROLE = "service"

# Set Logging Level
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def jwt_role_encode(jwt_secret, jwt_audience, jwt_issuer, subject, role, months=6):
    """
    Generate a JWT token for a subject that will last a number months of months after the current date.
    :param jwt_secret: String used for encrypted JWT signature 
    :param jwt_audience: Target site the JWT token will be authenticated against
    :param jwt_issuer: Organisation name of the principal issuer
    :param subject: Identifying attribute for the JWT token subject 
    :param role: Must be either 'service' or 'role'
    :param months: Number of months the token should expire from the current date
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
            'role': role
        }
        token = jwt.encode(payload, jwt_secret)
        return token
    except:
        logger.error("JWT encoding error: {}".format(sys.exc_info()[0]))
        raise

