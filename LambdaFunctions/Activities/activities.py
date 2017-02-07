'''
Activities Lambda handler code

Perform CRUD like actions on ANDS research activities.

'''

import boto3
import random

from boto3.dynamodb.conditions import Key
from boto3.session import Session

DYNAMO_DB_REGION =  os.environ['DYNAMO_DB_REGION']

# create an S3 & Dynamo session
s3 = boto3.resource('s3')
session = Session()

# Add Dynamo Region and Table
dynamodb = boto3.resource('dynamodb', DYNAMO_DB_REGION )
table_activities = dynamodb.Table('Activities')
table_researchers = dynamodb.Table('Researchers')
table_institutions = dynamodb.Table('Institutions')
table_activities_researchers  = dynamodb.Table('ActivitiesResearchers')

def activity_search_handler(event, context):
    '''
    Return list of research activities
    '''
    return {}

def activity_retrieve_handler(event, context):
    '''
    Return a single research activities and all related information
    '''
    return {}

def activity_create_handler(event, context):
    '''
    Register a new research activity
    '''
    return {}

def activity_update_handler(event, context):
    '''
    Update an existing research activity
    '''
    return {}
