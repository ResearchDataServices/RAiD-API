import requests
import base64
from xml.etree import ElementTree


class AndsMintingError(Exception):
    """
    Exception used for an unsuccessful content path and handle minting
    """
    pass


def build_basic_authorized_mint_body(identifier, auth_domain):
    xml_data = """
                <request name="mint">
                    <properties>
                        <property name="identifier" value="{}"/>
                        <property name="authDomain" value="{}"/>
                    </properties>
                </request>
                """.format(identifier, auth_domain)
    return xml_data


def build_ip_whitelist_mint_body(app_id, identifier, auth_domain):
    xml_data = """
                <request name="mint">
                    <properties>
                        <property name="appId" value="{}"/>
                        <property name="identifier" value="{}"/>
                        <property name="authDomain" value="{}"/>
                    </properties>
                </request>
                """.format(app_id, identifier, auth_domain)
    return xml_data


def build_internal_authorized_mint_body(app_id, shared_secret, identifier, auth_domain):
    xml_data = """
                <request name="mint">
                    <properties>
                        <property name="appId" value="{}"/>
                        <property name="sharedSecret" value="{}"/>
                        <property name="identifier" value="{}"/>
                        <property name="authDomain" value="{}"/>
                    </properties>
                </request>
                """.format(app_id, shared_secret, identifier, auth_domain)
    return xml_data


def ands_handle_request(url_path, app_id, identifier, auth_domain, shared_secret=None):
    """
    Build a minting (create/update) query for ANDS and parse XML response
    :param url_path:
    :param app_id:
    :param shared_secret:
    :param identifier:
    :param auth_domain:
    :return:
    """

    # Build Headers
    headers = {'Content-Type': 'application/xml'}

    if shared_secret:  # Basic Authenticated call
        # Create XML Body
        xml_data = build_basic_authorized_mint_body(identifier, auth_domain)

        # Build Headers
        encoded_app_secret = base64.b64encode('{}:{}'.format(app_id, shared_secret))
        authorization = 'Basic {}'.format(encoded_app_secret)
        headers['Authorization'] = authorization

    else:  # IP Address Whitelisted call
        # Create XML Body
        xml_data = build_ip_whitelist_mint_body(app_id, identifier, auth_domain)

    # Process response
    response = requests.post(url_path, data=xml_data, headers=headers)
    xml_tree = ElementTree.fromstring(response.content)

    # Get result of root XML tag response and read all child tags into a to dictionary
    if xml_tree.attrib["type"] == "success":
        response_data = {
            "handle": xml_tree.find("identifier").attrib["handle"],
            "contentIndex": xml_tree.find("identifier/property").attrib["index"],
            "timestamp": xml_tree.find("timestamp").text,
            "message": xml_tree.find("message").text
        }
        return response_data

    else:
        raise AndsMintingError(
            "Unable to mint content path for an ANDS handle.\n"
            "URL: \n"
            "{} \n"
            "Headers: \n"
            "{} \n"
            "Request: \n"
            "{} \n"
            "Response: \n"
            "{}\n".format(url_path, headers, xml_data, response.text)
        )
