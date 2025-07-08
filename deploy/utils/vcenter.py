import requests
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def refresh_vcenter_token(request):
    vcenter_url = request.session.get('vcenter_url')
    username = request.session.get('vcenter_username')
    password = request.session.get('vcenter_password')
    logger.info(f"Session data for token refresh: {dict(request.session.items())}")
    if not all([vcenter_url, username, password]):
        logger.error("Cannot refresh token: Missing vCenter session data")
        return None
    auth_url = f"{vcenter_url}/rest/com/vmware/cis/session"
    try:
        response = requests.post(auth_url, auth=(username, password), verify=False)
        if response.status_code == 200:
            token = response.json().get('value')
            request.session['vcenter_token'] = token
            logger.info("vCenter token refreshed successfully")
            return token
        logger.error(f"Failed to refresh token: {response.status_code} - {response.text}")
    except Exception as e:
        logger.error(f"Exception during token refresh: {str(e)}")
    return None

def fetch_from_vcenter(request, endpoint, method='get'):
    vcenter_url = request.session.get('vcenter_url')
    vcenter_token = request.session.get('vcenter_token')
    
    if not vcenter_url or not vcenter_token:
        logger.error("vCenter URL or token missing in session")
        return []

    url = f"{vcenter_url}{endpoint}"
    headers = {"vmware-api-session-id": vcenter_token}

    try:
        response = requests.request(method, url, headers=headers, verify=False)
        if response.status_code == 401:
            logger.info(f"Received 401 for {endpoint}, attempting token refresh")
            new_token = refresh_vcenter_token(request)
            if new_token:
                headers["vmware-api-session-id"] = new_token
                response = requests.request(method, url, headers=headers, verify=False)
            else:
                logger.error("Token refresh failed, returning empty result")
                return []
        
        if response.status_code == 200:
            data = response.json()
            if isinstance(data, dict):
                return data.get('value', [])
            elif isinstance(data, list):
                return data
            else:
                logger.warning(f"Unexpected response format from {endpoint}: {data}")
                return []
        logger.error(f"Error fetching {endpoint}: {response.status_code} - {response.text}")
        return []
    except Exception as e:
        logger.error(f"Exception parsing JSON from {endpoint}: {e}")
        return []

def get_datacenters(request):
    return fetch_from_vcenter(request, "/api/vcenter/datacenter")

def get_folders(request):
    all_folders = fetch_from_vcenter(request, "/api/vcenter/folder")
    vm_folders = [folder for folder in all_folders if folder.get("type") == "VIRTUAL_MACHINE"]
    logger.info(f"Filtered VM Folders: {vm_folders}")
    return vm_folders

def get_clusters(request):
    return fetch_from_vcenter(request, "/rest/vcenter/cluster")

def get_datastores(request):
    vcenter_url = request.session.get("vcenter_url")
    token = request.session.get("vcenter_token")
    if not vcenter_url or not token:
        logger.error("vCenter URL or session token is missing.")
        return []

    headers = {"vmware-api-session-id": token}
    tagging_url = f"{vcenter_url}/api/vcenter/tagging/associations"
    associations_response = requests.get(tagging_url, headers=headers, verify=False)

    if associations_response.status_code == 401:
        new_token = refresh_vcenter_token(request)
        if new_token:
            headers["vmware-api-session-id"] = new_token
            associations_response = requests.get(tagging_url, headers=headers, verify=False)
        else:
            return []

    if associations_response.status_code != 200:
        logger.error(f"Error fetching tag associations: {associations_response.text}")
        return []

    associations = associations_response.json().get("associations", [])
    datastore_tag_map = {}
    datastore_name_map = {}

    for association in associations:
        if association["object"]["type"] == "Datastore":
            datastore_id = association["object"]["id"]
            tag_id = association["tag"]
            if tag_id not in datastore_tag_map:
                datastore_tag_map[tag_id] = []
            datastore_tag_map[tag_id].append(datastore_id)

    tag_name_map = {}
    for tag_id in datastore_tag_map.keys():
        tag_url = f"{vcenter_url}/api/cis/tagging/tag/{tag_id}"
        tag_response = requests.get(tag_url, headers=headers, verify=False)
        if tag_response.status_code == 200:
            tag_data = tag_response.json()
            if isinstance(tag_data, dict) and "name" in tag_data:
                tag_name_map[tag_id] = tag_data["name"]
        else:
            logger.warning(f"Failed to fetch tag name for {tag_id}: {tag_response.text}")

    for tag_id, datastore_ids in datastore_tag_map.items():
        for datastore_id in datastore_ids:
            datastore_url = f"{vcenter_url}/api/vcenter/datastore/{datastore_id}"
            datastore_response = requests.get(datastore_url, headers=headers, verify=False)
            if datastore_response.status_code == 200:
                datastore_data = datastore_response.json()
                if isinstance(datastore_data, dict) and "name" in datastore_data:
                    datastore_name_map[datastore_id] = datastore_data["name"]
            else:
                logger.warning(f"Failed to fetch datastore name for {datastore_id}: {datastore_response.text}")

    datastores = []
    for tag_id, datastore_ids in datastore_tag_map.items():
        for datastore_id in datastore_ids:
            datastores.append({
                "tag": tag_name_map.get(tag_id, "Unknown Tag"),
                "datastore": datastore_id,
                "name": datastore_name_map.get(datastore_id, "Unknown Datastore")
            })
    logger.info(f"Final Datastore Mapping: {datastores}")
    return datastores

def get_networks(request):
    vcenter_url = request.session.get("vcenter_url")
    token = request.session.get("vcenter_token")
    if not vcenter_url or not token:
        logger.error("vCenter URL or session token is missing.")
        return []

    headers = {"vmware-api-session-id": token}
    network_url = f"{vcenter_url}/api/vcenter/network"
    network_response = requests.get(network_url, headers=headers, verify=False)

    if network_response.status_code == 401:
        new_token = refresh_vcenter_token(request)
        if new_token:
            headers["vmware-api-session-id"] = new_token
            network_response = requests.get(network_url, headers=headers, verify=False)
        else:
            return []

    if network_response.status_code != 200:
        logger.error(f"Error fetching networks: {network_response.text}")
        return []

    all_networks = network_response.json()
    network_name_map = {net["network"]: net["name"] for net in all_networks}

    tagging_url = f"{vcenter_url}/api/vcenter/tagging/associations"
    associations_response = requests.get(tagging_url, headers=headers, verify=False)

    if associations_response.status_code == 401:
        new_token = refresh_vcenter_token(request)
        if new_token:
            headers["vmware-api-session-id"] = new_token
            associations_response = requests.get(tagging_url, headers=headers, verify=False)
        else:
            return []

    if associations_response.status_code != 200:
        logger.error(f"Error fetching tag associations: {associations_response.text}")
        return []

    associations = associations_response.json().get("associations", [])
    network_tag_map = {}

    for association in associations:
        if association["object"]["type"] == "DistributedVirtualPortgroup":
            network_id = association["object"]["id"]
            tag_id = association["tag"]
            if tag_id not in network_tag_map:
                network_tag_map[tag_id] = []
            network_tag_map[tag_id].append(network_id)

    tag_name_map = {}
    for tag_id in network_tag_map.keys():
        tag_url = f"{vcenter_url}/api/cis/tagging/tag/{tag_id}"
        tag_response = requests.get(tag_url, headers=headers, verify=False)
        if tag_response.status_code == 200:
            tag_data = tag_response.json()
            if isinstance(tag_data, dict) and "name" in tag_data:
                tag_name_map[tag_id] = tag_data["name"]
        else:
            logger.warning(f"Failed to fetch tag name for {tag_id}: {tag_response.text}")

    networks = []
    for tag_id, network_ids in network_tag_map.items():
        for network_id in network_ids:
            networks.append({
                "tag": tag_name_map.get(tag_id, "Unknown Tag"),
                "network": network_id,
                "name": network_name_map.get(network_id, "Unknown Network")
            })
    logger.info(f"Final Network Mapping: {networks}")
    return networks

def get_templates(request):
    vcenter_url = request.session.get("vcenter_url")
    token = request.session.get("vcenter_token")
    if not vcenter_url or not token:
        logger.error("vCenter URL or session token is missing.")
        return []

    library_id = "1a99921b-12f2-4d09-b069-df62f29b595a"  # Verify this matches your environment
    headers = {"vmware-api-session-id": token}
    
    library_items_url = f"{vcenter_url}/api/content/library/item?library_id={library_id}"
    items_response = requests.get(library_items_url, headers=headers, verify=False)

    if items_response.status_code == 401:
        new_token = refresh_vcenter_token(request)
        if new_token:
            headers["vmware-api-session-id"] = new_token
            items_response = requests.get(library_items_url, headers=headers, verify=False)
        else:
            return []

    if items_response.status_code != 200:
        logger.error(f"Error fetching template IDs: {items_response.text}")
        return []

    template_ids = items_response.json()
    if not template_ids:
        logger.info("No templates found in the specified library.")
        return []

    template_list = []
    for template_id in template_ids:
        item_details_url = f"{vcenter_url}/api/content/library/item/{template_id}"
        item_response = requests.get(item_details_url, headers=headers, verify=False)
        if item_response.status_code == 200:
            item_details = item_response.json()
            template_list.append({"name": item_details.get("name"), "id": template_id})
    logger.info(f"Final Template List: {template_list}")
    return template_list