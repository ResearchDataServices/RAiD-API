import os


INSTITUTION_ROLE = "institution"
SERVICE_ROLE = "service"
RAID_TABLE = "RAID_TABLE"
ASSOCIATION_TABLE = "ASSOCIATION_TABLE"
CONTRIBUTORS_TABLE = "CONTRIBUTORS_TABLE"
CONTRIBUTOR_INVITATIONS_TABLE = "CONTRIBUTOR_INVITATIONS_TABLE"
RAID_CONTRIBUTORS_TABLE = "RAID_CONTRIBUTORS_TABLE"
DEMO_ENVIRONMENT = "demo"
LIVE_ENVIRONMENT = "live"
RAID_SITE_URL = "https://www.raid.org.au/"
ORCID_API_BASE_URL = "https://orcid.org"
ORCID_SANDBOX_API_BASE_URL = "https://sandbox.orcid.org"


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
    elif table_name == ASSOCIATION_TABLE:
        if environment == DEMO_ENVIRONMENT:
            return os.environ["ASSOCIATION_DEMO_TABLE"]
        elif environment == LIVE_ENVIRONMENT:
            return os.environ["ASSOCIATION_TABLE"]
    elif table_name == CONTRIBUTORS_TABLE:
        if environment == DEMO_ENVIRONMENT:
            return os.environ["CONTRIBUTORS_DEMO_TABLE"]
        elif environment == LIVE_ENVIRONMENT:
            return os.environ["CONTRIBUTORS_TABLE"]
    elif table_name == CONTRIBUTOR_INVITATIONS_TABLE:
        if environment == DEMO_ENVIRONMENT:
            return os.environ["CONTRIBUTOR_INVITATIONS_DEMO_TABLE"]
        elif environment == LIVE_ENVIRONMENT:
            return os.environ["CONTRIBUTOR_INVITATIONS_TABLE"]
    elif table_name == RAID_CONTRIBUTORS_TABLE:
        if environment == DEMO_ENVIRONMENT:
            return os.environ["RAID_CONTRIBUTORS_DEMO_TABLE"]
        elif environment == LIVE_ENVIRONMENT:
            return os.environ["RAID_CONTRIBUTORS_TABLE"]
