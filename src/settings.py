import os


INSTITUTION_ROLE = "institution"
SERVICE_ROLE = "service"
RAID_TABLE = "RAID_TABLE"
PROVIDER_TABLE = "PROVIDER_TABLE"
INSTITUTION_TABLE = "INSTITUTION_TABLE"
DEMO_ENVIRONMENT = "demo"
LIVE_ENVIRONMENT = "live"
RAID_SITE_URL = "https://www.raid.org.au/"


def get_environment_table(table_name, environment):
    """
    return the demo of live table name from environment variables
    :param table_name:
    :param environment:
    :return:
    """
    if table_name == RAID_TABLE:
        if environment == DEMO_ENVIRONMENT:
            return os.environ["RAID_DEMO_TABLE"]
        elif environment == LIVE_ENVIRONMENT:
            return os.environ["RAID_TABLE"]
    elif table_name == PROVIDER_TABLE:
        if environment == DEMO_ENVIRONMENT:
            return os.environ["PROVIDER_DEMO_TABLE"]
        elif environment == LIVE_ENVIRONMENT:
            return os.environ["PROVIDER_TABLE"]
    elif table_name == INSTITUTION_TABLE:
        if environment == DEMO_ENVIRONMENT:
            return os.environ["INSTITUTION_DEMO_TABLE"]
        elif environment == LIVE_ENVIRONMENT:
            return os.environ["INSTITUTION_TABLE"]
