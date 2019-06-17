def prettify_raid_contributors_list(db_items):
    """
    Convert sort key concatenated RAiD Contributor to a human-readable version
    :param db_items: Items return for the DynamoDB Query or Scan
    :return:
    """
    items = [{
        'orcid': '-'.join(item['orcid-startDate'].split('-')[:4]),
        'startDate': '-'.join(item['orcid-startDate'].split('-')[4:]),
        'endDate': None if 'endDate' not in item else item['endDate'],
        'provider': item['provider'],
        'role': item['role'],
        'description': item['description']
    } for item in db_items]

    return items
