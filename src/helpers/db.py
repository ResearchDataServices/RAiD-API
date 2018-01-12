from boto3.dynamodb.conditions import Key, Attr
import settings
from helpers import raid_helpers


def end_provider_ownership(table, handle, owner_name, raid_name):
    """
    convert the current owner in the index to a standard provider
    :param table:
    :param handle:
    :param owner_name:
    :param raid_name:
    :return:
    """
    # Change association of current owner
    current_owner_query_parameters = {
        'IndexName': 'HandleNameIndex',
        'ProjectionExpression': "startDate, endDate",
        'FilterExpression': Attr('endDate').not_exists(),
        'KeyConditionExpression': Key('handle-name').eq('{}-{}'.format(handle, owner_name))
    }

    current_owner_query_response = table.query(**current_owner_query_parameters)
    current_owner = current_owner_query_response["Items"][0]

    # Remove indexed previous owner
    table.delete_item(
        Key={
            'startDate': current_owner['startDate'],
            'handle': handle
        },
        ReturnValues='ALL_OLD'
    )

    # Create new associations
    previous_owner_item = {
        'handle': handle,
        'startDate': current_owner['startDate'],
        'name': owner_name,
        'raidName': raid_name,
        'type': settings.SERVICE_ROLE,
        'handle-name': '{}-{}'.format(handle, owner_name),
        'handle-type': '{}-{}'.format(handle, settings.SERVICE_ROLE)
    }

    table.put_item(Item=previous_owner_item)


def create_provider_ownership(table, handle, new_owner_name, raid_name):
    """
    Create ownership index for a new provider or convert existing one
    :param table:
    :param handle:
    :param new_owner_name:
    :param raid_name:
    :return:
    """
    # Get current datetime
    association_datetime = raid_helpers.get_current_datetime()

    # Check if new owner exists and end normal association
    existing_provider_query_parameters = {
        'IndexName': 'HandleNameIndex',
        'ProjectionExpression': "startDate, endDate",
        'FilterExpression': Attr('endDate').not_exists(),
        'KeyConditionExpression': Key('handle-name').eq('{}-{}'.format(handle, new_owner_name))
    }

    existing_provider_query_response = table.query(**existing_provider_query_parameters)
    existing_providers = existing_provider_query_response["Items"]

    if existing_provider_query_response["Count"] > 0:
        association_datetime = existing_providers[0]['startDate']

        # Remove indexed previous owner
        table.delete_item(
            Key={
                'startDate': existing_providers[0]['startDate'],
                'handle': handle
            },
            ReturnValues='ALL_OLD'
        )
    # Create new association
    new_owner_item = {
        'handle': handle,
        'startDate': association_datetime,
        'name': new_owner_name,
        'raidName': raid_name,
        'type': settings.SERVICE_ROLE,
        'handle-name': '{}-{}'.format(handle, new_owner_name),
        'handle-type': '{}-{}'.format(handle, settings.SERVICE_ROLE),
        'role': 'owner',
        'name-role': '{}-{}'.format(new_owner_name, 'owner'),
    }
    table.put_item(Item=new_owner_item)
