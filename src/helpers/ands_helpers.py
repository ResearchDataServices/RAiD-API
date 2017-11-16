import requests
from xml.etree import ElementTree


class AndsMintingError(Exception):
    """
    Exception used for an unsuccessful content path and handle minting
    """
    pass


def ands_handle_request(url_path, app_id, identifier, auth_domain):
    """
    Build a minting (create/update) query for ANDS and parse XML response
    :param url_path:
    :param app_id:
    :param identifier:
    :param auth_domain:
    :return:
    """
    xml_data = """
                <request name="mint">
                    <properties>
                        <property name="appId" value="{}"/>
                        <property name="identifier" value="{}"/>
                        <property name="authDomain" value="{}"/>
                    </properties>
                </request>
                """.format(app_id, identifier, auth_domain)
    headers = {'Content-Type': 'application/xml'}
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
        raise AndsMintingError("Unable to mint content path for an ANDS handle: {}".format(
            xml_tree.find("message").text))
