#! /usr/bin/env python3
#
# Example RAiD provider integration

import sys
import os.path
import os
import json
import requests
import urllib.parse

API_KEY = '<<JWT TOKEN>>'
BASE_URL = 'https://api.raid.org.au/v1'

# main upload routine
if __name__ == "__main__":
    # Header object for restricted api routes using 'Authorization:Bearer <<token>>'
    raid_headers = {
        "Authorization": "Bearer {}".format(API_KEY),
        "Content-Type": "application/json"
    }

    # Check RAiD API Version
    print("1. Get RAiD API version (Public API)")
    response = requests.get(url=BASE_URL)
    print(BASE_URL)
    print("Status code: " + str(response.status_code))
    if response.status_code < 200 or response.status_code >= 300:
        raise Exception("Failed to get RAiD.")
    else:
        print("API version: " + response.json()['version'])

    # Create a RAiD
    print("2. Create RAiD")
    create_body = {
        'contentPath': 'http://myorganisation.org.au/contentlocation',
        'description': 'My first RAiD',  # Optional
        'startDate': '2017-09-11 00:00:00',  # Optional(yyyy-MM-dd hh:mm:ss)
        'meta': {  # Optional(object)
            'purpose': "testing"
        }
    }
    response = requests.post(headers=raid_headers, url="{}/RAiD".format(BASE_URL), data=json.dumps(create_body))
    print("{}/RAiD".format(BASE_URL))
    print("Status code: " + str(response.status_code))
    print(json.dumps(response.json()))
    if response.status_code != 200:
        raise Exception("Unable to create RAiD.")

    # Get the created RAiD handle
    raid_handle = urllib.parse.quote_plus(response.json()["raid"]["handle"])

    # Associate another provider
    print("3. Associate another provider to RAiD")
    associate_url = "{}/RAiD/{}/providers".format(BASE_URL, raid_handle)
    response = requests.post(headers=raid_headers, url=associate_url, data=json.dumps({'provider': 'AAF'}))
    print(associate_url)
    print("Status code: " + str(response.status_code))
    print(json.dumps(response.json()))
    if response.status_code != 200:
        raise Exception("Unable to associate another provider to the RAiD.")

    # Check if a given RAiD handle is valid
    valid_raid_url = "{}/handle/{}".format(BASE_URL, raid_handle)

    print("4. Check if RAiD exists in the demo environment(Public API)")
    response = requests.get(url=valid_raid_url, params={'demo': True})
    print("{}?demo=True".format(valid_raid_url))
    print("Status code: " + str(response.status_code))
    print(response.json())

    print("5. Check if RAiD exists in the live environment(Public API)")
    response = requests.get(url=valid_raid_url)
    print(valid_raid_url)
    print("Status code: " + str(response.status_code))
    print(response.json())

    # Get The full RAiD object
    print("6. Get the full RAiD object using the handle")
    valid_raid_url = "{}/RAiD/{}".format(BASE_URL, raid_handle)
    response = requests.get(headers=raid_headers, url=valid_raid_url, params={'lazy_load': False})
    print("Status code: " + str(response.status_code))
    print(response.json())

    # Get all RAiDs I own as a provider
    print("7. Get all RAiD object that I own")
    valid_raid_url = "{}/owner".format(BASE_URL)
    response = requests.get(headers=raid_headers, url=valid_raid_url)
    print("Status code: " + str(response.status_code))
    print(response.json())
