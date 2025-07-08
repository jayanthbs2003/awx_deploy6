from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponse, HttpResponseRedirect
import requests
import logging
from requests.auth import HTTPBasicAuth
from django.views.decorators.csrf import csrf_exempt
from .utils.vcenter import get_clusters, get_datastores, get_networks, get_templates, get_datacenters, get_folders
from .models import VMDeployment, VMActivity  # Add VMActivity here
import time

logger = logging.getLogger(__name__)

@csrf_exempt
def login_page(request):
    vcenter_urls = ["https://coevcenter.lenovo.com", "https://backupvcenter.lenovo.com" ,"https://testvc.coelab.com"]
    return render(request, "deploy/login.html", {"vcenter_urls": vcenter_urls})

@csrf_exempt
def authenticate_vcenter(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        vcenter_url = request.POST.get("vcenter_url")
        auth_url = f"{vcenter_url}/rest/com/vmware/cis/session"
        
        response = requests.post(auth_url, auth=(username, password), verify=False)
        
        if response.status_code == 200:
            request.session['vcenter_token'] = response.json().get('value')
            request.session['vcenter_url'] = vcenter_url
            request.session['vcenter_username'] = username
            request.session['vcenter_password'] = password
            return redirect("deploy_vm")
        else:
            return render(request, "deploy/login.html", {"error": "Invalid credentials"})
    return redirect("login_page")

def deploy_vm_view(request):
    if 'vcenter_token' not in request.session:
        return redirect("/login/")
    return render(request, "deploy/deploy_vm.html")

def create_vm_view(request):
    if 'vcenter_token' not in request.session:
        return redirect("login_page")
    return render(request, "deploy/create_vm.html")

def vm_list_view(request):
    if 'vcenter_token' not in request.session:
        return redirect("login_page")
    vms = get_vms(request)
    if isinstance(vms, dict) and "error" in vms:
        return render(request, "deploy/vm_list.html", {"vms": []})
    return render(request, "deploy/vm_list.html", {"vms": vms})

def load_clusters(request):
    return render(request, "deploy/partials/clusters.html", {"clusters": get_clusters(request)})

def load_datastores(request):
    datastore_tags = get_datastores(request)
    print("Datastore Tags Sent to Template:", datastore_tags)
    return render(request, "deploy/partials/datastores.html", {"datastores": datastore_tags})

def load_networks(request):
    return render(request, "deploy/partials/networks.html", {"networks": get_networks(request)})

def load_datacenters(request):
    return render(request, "deploy/partials/datacenters.html", {"datacenters": get_datacenters(request)})

def load_folders(request):
    folders = get_folders(request)
    print("Loaded Folders:", folders)
    return render(request, "deploy/partials/folders.html", {"folders": folders})

def load_templates(request):
    templates = get_templates(request)
    template_options = "".join([f'<option value="{t["id"]}">{t["name"]}</option>' for t in templates])
    return HttpResponse(template_options)

def get_vm_details(request, vm_name):
    """Fetch VM hardware details (CPU, Memory, Disk, Uptime, OS) using vSphere REST API."""
    vcenter_url = request.session.get('vcenter_url')
    vcenter_token = request.session.get('vcenter_token')

    if not vcenter_url or not vcenter_token:
        return {"error": "vCenter authentication required"}

    headers = {"vmware-api-session-id": vcenter_token, "Accept": "application/json"}
    max_retries = 3
    retry_delay = 5  # seconds

    for attempt in range(max_retries):
        try:
            # 1. Get All VMs to Find VM ID
            vms_url = f"{vcenter_url}/rest/vcenter/vm"
            vms_response = requests.get(vms_url, headers=headers, verify=False)

            if vms_response.status_code == 200:
                vms = vms_response.json().get("value", [])
                vm_id = None
                for vm in vms:
                    if vm["name"].lower() == vm_name.lower():  # Case-insensitive comparison
                        vm_id = vm["vm"]
                        break

                if not vm_id:
                    logger.error(f"VM {vm_name} not found in vCenter")
                    return {"error": "VM not found"}

                # 2. Fetch VM Hardware Details
                vm_details_url = f"{vcenter_url}/rest/vcenter/vm/{vm_id}"
                vm_details_response = requests.get(vm_details_url, headers=headers, verify=False)

                if vm_details_response.status_code == 200:
                    vm_data = vm_details_response.json().get("value", {})
                    cpu_count = vm_data.get("cpu", {}).get("count", "N/A")
                    memory_mb = vm_data.get("memory", {}).get("size_MiB", "N/A")
                    disk_gb = "N/A"
                    guest_os = vm_data.get("guest_OS", "Unknown")

                    # Map guest_OS to simplified name
                    os_display = "Unknown"
                    if "LINUX" in guest_os.upper():
                        os_display = "Linux"
                    elif "WINDOWS" in guest_os.upper():
                        os_display = "Windows"

                    # 3. Fetch Disk Information
                    disk_info = vm_data.get("disks", [])
                    logger.info(f"Raw disk response for {vm_name}: {vm_data}")
                    logger.info(f"Disk info for {vm_name}: {disk_info}")
                    total_disk_bytes = sum(disk.get("value", {}).get("capacity", 0) for disk in disk_info)
                    disk_gb = round(total_disk_bytes / (1024 * 1024 * 1024), 2)
                    logger.info(f"Calculated disk capacity for {vm_name}: {disk_gb} GB")

                    memory_gb = round(memory_mb / 1024, 2) if memory_mb != "N/A" else "N/A"

                    # 4. Fetch Power State and Uptime
                    power_url = f"{vcenter_url}/rest/vcenter/vm/{vm_id}/power"
                    power_response = requests.get(power_url, headers=headers, verify=False)
                    uptime = "N/A"
                    if power_response.status_code == 200:
                        power_data = power_response.json().get("value", {})
                        if power_data.get("state") == "POWERED_ON":
                            guest_url = f"{vcenter_url}/rest/vcenter/vm/{vm_id}/guest/power"
                            guest_response = requests.get(guest_url, headers=headers, verify=False)
                            if guest_response.status_code == 200:
                                guest_data = guest_response.json().get("value", {})
                                boot_time = guest_data.get("last_boot_time")
                                if boot_time:
                                    from datetime import datetime
                                    boot_dt = datetime.fromisoformat(boot_time.replace("Z", "+00:00"))
                                    now = datetime.utcnow().replace(tzinfo=boot_dt.tzinfo)
                                    uptime_seconds = (now - boot_dt).total_seconds()
                                    uptime_days = uptime_seconds // (24 * 3600)
                                    uptime_hours = (uptime_seconds % (24 * 3600)) // 3600
                                    uptime = f"{int(uptime_days)}d {int(uptime_hours)}h"
                                else:
                                    uptime = "Running"
                            else:
                                uptime = "Running (Guest info unavailable)"
                        else:
                            uptime = "Powered Off"
                    else:
                        logger.error(f"Failed to fetch power state for VM {vm_name}: {power_response.status_code} - {power_response.text}")
                        if power_response.status_code in [503, 401] and attempt < max_retries - 1:
                            logger.info(f"Retrying after {retry_delay} seconds due to {power_response.status_code} error")
                            time.sleep(retry_delay)
                            continue
                        return {"error": "Failed to fetch power state"}

                    return [{
                        "name": vm_name,
                        "cpu": cpu_count,
                        "memory": memory_gb,
                        "disk": disk_gb,
                        "uptime": uptime,
                        "os": os_display
                    }]
                elif vm_details_response.status_code in [401, 403]:
                    logger.warning(f"Authentication expired for VM {vm_name}, attempt {attempt + 1}")
                    if attempt < max_retries - 1:
                        # Re-authenticate
                        username = request.session.get('vcenter_username')
                        password = request.session.get('vcenter_password')
                        auth_url = f"{vcenter_url}/rest/com/vmware/cis/session"
                        session_response = requests.post(auth_url, auth=(username, password), verify=False)
                        if session_response.status_code == 200:
                            vcenter_token = session_response.json()['value']
                            request.session['vcenter_token'] = vcenter_token
                            request.session.modified = True
                            headers["vmware-api-session-id"] = vcenter_token
                            logger.info(f"Re-authenticated successfully for VM {vm_name}")
                            time.sleep(retry_delay)
                            continue
                        else:
                            logger.error(f"Failed to re-authenticate: {session_response.status_code} - {session_response.text}")
                            return {"error": "Authentication expired, please re-login"}
                    return {"error": "Authentication expired, please re-login"}
                else:
                    logger.error(f"Failed to fetch VM details for {vm_name}: {vm_details_response.status_code} - {vm_details_response.text}")
                    return {"error": "Failed to fetch VM details"}
            elif vms_response.status_code in [401, 403]:
                logger.warning(f"Authentication expired while fetching VM list, attempt {attempt + 1}")
                if attempt < max_retries - 1:
                    username = request.session.get('vcenter_username')
                    password = request.session.get('vcenter_password')
                    auth_url = f"{vcenter_url}/rest/com/vmware/cis/session"
                    session_response = requests.post(auth_url, auth=(username, password), verify=False)
                    if session_response.status_code == 200:
                        vcenter_token = session_response.json()['value']
                        request.session['vcenter_token'] = vcenter_token
                        request.session.modified = True
                        headers["vmware-api-session-id"] = vcenter_token
                        logger.info("Re-authenticated successfully")
                        time.sleep(retry_delay)
                        continue
                    else:
                        logger.error(f"Failed to re-authenticate: {session_response.status_code} - {session_response.text}")
                        return {"error": "Authentication expired, please re-login"}
                return {"error": "Authentication expired, please re-login"}
            else:
                logger.error(f"Failed to fetch VM list: {vms_response.status_code} - {vms_response.text}")
                if vms_response.status_code == 503 and attempt < max_retries - 1:
                    logger.info(f"Retrying after {retry_delay} seconds due to 503 error")
                    time.sleep(retry_delay)
                    continue
                return {"error": "Failed to fetch VM list"}
        except Exception as e:
            logger.error(f"Error fetching details for VM {vm_name}, attempt {attempt + 1}: {str(e)}")
            if attempt < max_retries - 1:
                logger.info(f"Retrying after {retry_delay} seconds due to exception")
                time.sleep(retry_delay)
                continue
            return {"error": f"Server error: {str(e)}"}

    return {"error": f"Failed to fetch VM details for {vm_name} after {max_retries} attempts"}

def get_vms(request):
    """Fetch all VMs from vCenter (raw data)."""
    vcenter_url = request.session.get('vcenter_url')
    vcenter_token = request.session.get('vcenter_token')

    if not vcenter_url or not vcenter_token:
        return redirect("login_page")

    headers = {"vmware-api-session-id": vcenter_token, "Accept": "application/json"}
    vms_url = f"{vcenter_url}/rest/vcenter/vm"
    try:
        vms_response = requests.get(vms_url, headers=headers, verify=False)
        if vms_response.status_code == 200:
            vms = vms_response.json().get("value", [])
            logger.info(f"Raw VMs fetched: {vms}")
            return vms
        elif vms_response.status_code in [401, 403]:
            logger.warning("Invalid or expired vCenter token. Redirecting to login.")
            request.session.clear()
            return redirect("login_page")
        else:
            logger.error(f"Failed to fetch VMs: {vms_response.status_code} - {vms_response.text}")
            return []
    except Exception as e:
        logger.error(f"Error fetching VMs: {str(e)}")
        return []

def vm_list(request):
    """Render all deployed VMs, deduplicated by name."""
    if 'vcenter_token' not in request.session:
        return redirect("login_page")

    vm_deployments = VMDeployment.objects.filter(status="Successful")  # Only successful deployments
    vms = []
    seen_names = set()  # Track unique VM names to avoid duplicates

    for vm in vm_deployments:
        if vm.vm_name not in seen_names:
            vm_details = get_vm_details(request, vm.vm_name)
            if isinstance(vm_details, list):
                vms.append(vm_details[0])
                seen_names.add(vm.vm_name)
            else:
                logger.warning(f"Skipping {vm.vm_name}: Failed to fetch details - {vm_details}")

    return render(request, "deploy/vm_table.html", {"vms": vms})


def create_vm(request):
    if request.method == "POST":
        try:
            logger.info("Received request data: %s", request.POST)
            datacenter_id = request.POST.get("datacenter")
            folder_id = request.POST.get("folder")
            vm_name = request.POST.get("vm_name")
            cluster_id = request.POST.get("cluster")
            datastore_id = request.POST.get("datastore")
            network_id = request.POST.get("network")
            template_id = request.POST.get("template")

            if 'vcenter_token' not in request.session:
                return JsonResponse({"error": "vCenter authentication required"}, status=403)

            datacenters = get_datacenters(request)
            folders = get_folders(request)
            clusters = {c["cluster"]: c["name"] for c in get_clusters(request)}
            datastore_map = {d["datastore"]: d["name"] for d in get_datastores(request)}
            network_map = {n["network"]: n["name"] for n in get_networks(request)}
            templates = {t["id"]: t["name"] for t in get_templates(request)}

            datacenter_name = next((dc["name"] for dc in datacenters if dc.get("datacenter") == datacenter_id), f"Unknown: {datacenter_id}")
            folder_name = next((f["name"] for f in folders if f.get("folder") == folder_id), f"Unknown: {folder_id}")
            cluster_name = clusters.get(cluster_id, f"Unknown: {cluster_id}")
            datastore_name = datastore_map.get(datastore_id, f"Unknown: {datastore_id}")
            network_name = network_map.get(network_id, f"Unknown: {network_id}")
            template_name = templates.get(template_id, f"Unknown: {template_id}")
            folder_path = f"{datacenter_name}/vm/{folder_name}"
            
            vm_deployment = VMDeployment.objects.create(
                vm_name=vm_name,
                cluster=cluster_name,
                datastore=datastore_name,
                network=network_name,
                template=template_name,
                status="Pending"
            )
            vm_deployment.save()

            # Log the initial activity
            VMActivity.objects.create(
                vm_name=vm_name,
                message="VM deployment triggered",
            )

            payload = {
                "extra_vars": {
                    "vm_name": vm_name,
                    "cluster": cluster_name,
                    "datastore": datastore_name,
                    "network": network_name,
                    "template": template_name,
                    "datacenter": datacenter_name,
                    "folder": folder_path                   
                }
            }

            logger.info("Final payload sent to AWX: %s", payload)

            awx_url = "https://rocky.lenovo.com/api/v2/job_templates/182/launch/"
            awx_username = "admin"
            awx_password = "Lenovo@123"

            response = requests.post(
                awx_url, 
                json=payload, 
                auth=HTTPBasicAuth(awx_username, awx_password),
                headers={"Content-Type": "application/json"},
                verify=False
            )

            logger.info("AWX Response: %s", response.text)
            # Initial activity
            logger.info(f"Creating VMActivity for triggered state: {vm_name}")
            VMActivity.objects.create(
                vm_name=vm_name,
                message=f"{vm_name} - VM deployment triggered"
            )

            if response.status_code == 201:
                job_id = response.json().get("job", None)
                if job_id:
                    logger.info(f"AWX Job ID: {job_id}")
                    awx_job_url = f"https://rocky.lenovo.com/api/v2/jobs/{job_id}/"
                    max_attempts = 6  # Wait up to 60 seconds (6 * 10s)
                    attempt = 0
                    
                    while attempt < max_attempts:
                        job_response = requests.get(
                            awx_job_url,
                            auth=HTTPBasicAuth(awx_username, awx_password),
                            headers={"Content-Type": "application/json"},
                            verify=False
                        )
                        if job_response.status_code == 200:
                            job_data = job_response.json()
                            job_status = job_data.get("status")
                            logger.info(f"Job {job_id} status after {attempt+1} attempts: {job_status}")
                            if job_status == "successful":
                                vm_deployment.status = "Successful"
                                request.session['new_vm_name'] = vm_name
                                logger.info(f"Creating VMActivity for successful state: {vm_name}")
                                VMActivity.objects.create(
                                    vm_name=vm_name,
                                    message=f"{vm_name} - VM successfully deployed"
                                )
                                break
                            elif job_status in ["failed", "error", "canceled"]:
                                vm_deployment.status = "Failed"
                                logger.info(f"Creating VMActivity for failed state: {vm_name}")
                                VMActivity.objects.create(
                                    vm_name=vm_name,
                                    message=f"{vm_name} - VM deployment failed: {job_status}"
                                )
                                break
                        else:
                            logger.error("Failed to fetch job status from AWX")
                            break
                        attempt += 1
                        time.sleep(10)  # Wait 10 seconds between checks
                    
                    # If loop exits without success or failure, assume running and check vCenter
                    if attempt == max_attempts:
                        logger.info(f"Job {job_id} still running after {max_attempts} attempts, checking vCenter for {vm_name}")
                        vm_details = get_vm_details(request, vm_name)
                        if isinstance(vm_details, list) and vm_details:  # VM exists in vCenter
                            vm_deployment.status = "Successful"
                            request.session['new_vm_name'] = vm_name
                            VMActivity.objects.create(
                                vm_name=vm_name,
                                message=f"{vm_name} - VM successfully deployed (confirmed via vCenter)"
                            )
                        else:
                            vm_deployment.status = "Failed"
                            VMActivity.objects.create(
                                vm_name=vm_name,
                                message=f"{vm_name} - VM deployment failed: timeout"
                            )
                    
                    vm_deployment.save()
                    logger.info(f"VM Deployment {vm_name} status updated to {vm_deployment.status}")
                
                return redirect("vm_list")
            else:
                return JsonResponse({"error": response.text}, status=response.status_code)
        except Exception as e:
            logger.error("Error in create_vm: %s", str(e), exc_info=True)
            return JsonResponse({"error": str(e)}, status=500)
    return JsonResponse({"error": "Invalid request method"}, status=400)

@csrf_exempt
def delete_vms(request):
    if request.method == "POST":
        if 'vcenter_token' not in request.session:
            return JsonResponse({"error": "vCenter authentication required"}, status=403)

        vcenter_url = request.session.get('vcenter_url')
        vcenter_token = request.session.get('vcenter_token')
        headers = {"vmware-api-session-id": vcenter_token, "Accept": "application/json"}

        vm_names = request.POST.getlist("vm_to_delete")
        logger.info(f"Received VM names to delete: {vm_names}")

        if not vm_names:
            vms = []
            vm_deployments = VMDeployment.objects.all()
            for vm in vm_deployments:
                vm_details = get_vm_details(request, vm.vm_name)
                if isinstance(vm_details, list):
                    vms.extend(vm_details)
            return render(request, "deploy/vm_table.html", {
                "vms": vms,
                "error_message": "No VMs selected for deletion"
            })

        vms_url = f"{vcenter_url}/rest/vcenter/vm"
        vms_response = requests.get(vms_url, headers=headers, verify=False)

        if vms_response.status_code != 200:
            return JsonResponse({"error": "Failed to fetch VM list from vCenter"}, status=500)

        vms = vms_response.json().get("value", [])
        vm_ids_to_delete = {vm["name"]: vm["vm"] for vm in vms if vm["name"] in vm_names}

        for vm_name in vm_names:
            vm_id = vm_ids_to_delete.get(vm_name)
            if vm_id:
                power_url = f"{vcenter_url}/rest/vcenter/vm/{vm_id}/power/stop"
                power_response = requests.post(power_url, headers=headers, verify=False)
                if power_response.status_code not in [200, 204]:
                    logger.warning(f"Failed to power off VM {vm_name}: {power_response.text}")

                delete_url = f"{vcenter_url}/rest/vcenter/vm/{vm_id}"
                delete_response = requests.delete(delete_url, headers=headers, verify=False)
                if delete_response.status_code == 200:
                    VMDeployment.objects.filter(vm_name=vm_name).delete()
                    logger.info(f"Successfully deleted VM {vm_name}")
                else:
                    logger.error(f"Failed to delete VM {vm_name}: {delete_response.text}")
            else:
                logger.warning(f"VM {vm_name} not found in vCenter")

        vms = []
        vm_deployments = VMDeployment.objects.all()
        for vm in vm_deployments:
            vm_details = get_vm_details(request, vm.vm_name)
            if isinstance(vm_details, list):
                vms.extend(vm_details)

        return render(request, "deploy/vm_table.html", {"vms": vms})
    
    return JsonResponse({"error": "Invalid request method"}, status=400)

def recent_activity(request):
    """Fetch the 5 most recent VM deployment activities."""
    activities = VMActivity.objects.order_by('-timestamp')[:5]
    logger.info(f"Recent activities fetched: {[str(a) for a in activities]}")
    return render(request, "deploy/partials/activity_feed.html", {"activities": activities})


# Add this new function to fetch host details
def get_hosts(request):
    """Fetch all hosts from vCenter."""
    vcenter_url = request.session.get('vcenter_url')
    vcenter_token = request.session.get('vcenter_token')

    if not vcenter_url or not vcenter_token:
        return {"error": "vCenter authentication required"}

    headers = {"vmware-api-session-id": vcenter_token, "Accept": "application/json"}
    hosts_url = f"{vcenter_url}/rest/vcenter/host"
    hosts_response = requests.get(hosts_url, headers=headers, verify=False)

    if hosts_response.status_code == 200:
        hosts = hosts_response.json().get("value", [])
        host_details_list = []
        for host in hosts:
            host_id = host["host"]
            host_name = host["name"]
            connection_state = host["connection_state"]
            power_state = host["power_state"]

            # IP address isn’t directly available in this API response; set to "N/A" for now
            # Extend this logic if you have a way to fetch IPs (e.g., via network config or another API)
            ip_address = "N/A"

            host_details_list.append({
                "name": host_name,
                "ip_address": ip_address,
                "connection_state": connection_state,
                "power_state": power_state
            })
        return host_details_list
    return {"error": "Failed to fetch hosts"}

# Add a view to render the host table
def host_list(request):
    """Render all hosts in a table."""
    if 'vcenter_token' not in request.session:
        return redirect("login_page")
    hosts = get_hosts(request)
    if isinstance(hosts, dict) and "error" in hosts:
        return render(request, "deploy/host_table.html", {"hosts": []})
    return render(request, "deploy/host_table.html", {"hosts": hosts})

def vm_details_view(request):
    if 'vcenter_token' not in request.session:
        return redirect("/login/")
    vm_name = request.GET.get('vm_name')  # Extract vm_name from query parameter
    return render(request, "deploy/vm_details.html", {'vm_name': vm_name})



def deploy_vm_view(request):
    if 'vcenter_token' not in request.session:
        return redirect("/login/")
    vm_name = request.GET.get('vm_name')  # Extract vm_name from query parameter
    return render(request, "deploy/deploy_vm.html", {'vm_name': vm_name})

def get_vm_summary(request):
    """Fetch detailed VM summary data from vCenter for display on the dashboard."""
    vcenter_url = request.session.get('vcenter_url')
    vcenter_token = request.session.get('vcenter_token')
    vm_name = request.GET.get('vm_name')  # Get the specific VM name if provided

    logger.info(f"Fetching VM summary for vm_name: {vm_name}")

    if not vcenter_url or not vcenter_token:
        logger.error("vCenter authentication required: URL or token missing")
        return JsonResponse({"error": "vCenter authentication required"}, status=403)

    headers = {"vmware-api-session-id": vcenter_token, "Accept": "application/json"}
    vms_url = f"{vcenter_url}/rest/vcenter/vm"
    logger.info(f"Requesting VM list from: {vms_url}")
    try:
        vms_response = requests.get(vms_url, headers=headers, verify=False)
    except Exception as e:
        logger.error(f"Exception while fetching VMs: {str(e)}")
        return JsonResponse({"error": f"Failed to connect to vCenter: {str(e)}"}, status=500)

    if vms_response.status_code == 401:
        logger.error("vCenter session expired, redirecting to login")
        request.session.flush()
        return render(request, "deploy/partials/vm_summary.html", {
            "vms": [],
            "vm_name": vm_name,
            "error": "Session expired, please re-login"
        })
    elif vms_response.status_code != 200:
        logger.error(f"Failed to fetch VMs: {vms_response.status_code} - {vms_response.text}")
        return JsonResponse({"error": "Failed to fetch VMs"}, status=500)

    vms = vms_response.json().get("value", [])
    vm_details_list = []

    # Fetch all datastores, hosts, and clusters for mapping
    datastores_url = f"{vcenter_url}/rest/vcenter/datastore"
    datastores_response = requests.get(datastores_url, headers=headers, verify=False)
    datastore_map = {}
    datastore_name_to_id = {}
    if datastores_response.status_code == 200:
        datastores = datastores_response.json().get("value", [])
        datastore_map = {ds["datastore"]: ds["name"] for ds in datastores}
        datastore_name_to_id = {ds["name"]: ds["datastore"] for ds in datastores}
        logger.info(f"Datastores fetched: {datastore_map}")
        logger.info(f"Datastore name to ID mapping: {datastore_name_to_id}")
    else:
        logger.error(f"Failed to fetch datastores: {datastores_response.status_code} - {datastores_response.text}")

    hosts_url = f"{vcenter_url}/rest/vcenter/host"
    hosts_response = requests.get(hosts_url, headers=headers, verify=False)
    host_map = {}
    host_to_cluster_map = {}
    host_details = []
    if hosts_response.status_code == 200:
        hosts = hosts_response.json().get("value", [])
        host_map = {host["host"]: host["name"] for host in hosts}
        host_to_cluster_map = {host["host"]: host.get("cluster") for host in hosts}
        # Format host details similar to what /hosts/ endpoint might return
        host_details = [
            {
                "host": host["host"],
                "name": host["name"],
                "connection_state": host.get("connection_state", "UNKNOWN"),
                "power_state": host.get("power_state", "UNKNOWN")
            }
            for host in hosts
        ]
        logger.info(f"Hosts fetched: {host_map}")
        logger.info(f"Host to Cluster mapping: {host_to_cluster_map}")
        logger.info(f"Host details: {host_details}")
    else:
        logger.error(f"Failed to fetch hosts: {hosts_response.status_code} - {hosts_response.text}")

    clusters_url = f"{vcenter_url}/rest/vcenter/cluster"
    clusters_response = requests.get(clusters_url, headers=headers, verify=False)
    cluster_map = {}
    cluster_to_hosts_map = {}
    if clusters_response.status_code == 200:
        clusters = clusters_response.json().get("value", [])
        cluster_map = {cluster["cluster"]: cluster["name"] for cluster in clusters}
        for cluster_id, cluster_name in cluster_map.items():
            cluster_to_hosts_map[cluster_name] = []
            for host_id, mapped_cluster_id in host_to_cluster_map.items():
                if mapped_cluster_id == cluster_id:
                    cluster_to_hosts_map[cluster_name].append(host_map.get(host_id))
        logger.info(f"Clusters fetched: {cluster_map}")
        logger.info(f"Cluster to Hosts mapping: {cluster_to_hosts_map}")
    else:
        logger.error(f"Failed to fetch clusters: {clusters_response.status_code} - {clusters_response.text}")

    target_vms = [vm for vm in vms if vm_name is None or vm["name"] == vm_name]
    if vm_name and not target_vms:
        logger.warning(f"No VMs found matching vm_name: {vm_name}")
        return render(request, "deploy/partials/vm_summary.html", {"vms": [], "vm_name": vm_name})

    for vm in target_vms:
        try:
            vm_id = vm["vm"]
            vm_name = vm["name"]
            logger.info(f"Processing VM: {vm_name} (ID: {vm_id})")

            # Fetch VM Details
            vm_details_url = f"{vcenter_url}/rest/vcenter/vm/{vm_id}"
            logger.info(f"Fetching VM details from: {vm_details_url}")
            vm_details_response = requests.get(vm_details_url, headers=headers, verify=False)

            if vm_details_response.status_code == 401:
                logger.error("vCenter session expired during VM details fetch, redirecting to login")
                request.session.flush()
                return render(request, "deploy/partials/vm_summary.html", {
                    "vms": [],
                    "vm_name": vm_name,
                    "error": "Session expired, please re-login"
                })
            elif vm_details_response.status_code != 200:
                logger.error(f"Failed to fetch VM details for {vm_name}: {vm_details_response.status_code} - {vm_details_response.text}")
                continue

            vm_data = vm_details_response.json().get("value", {})
            logger.info(f"Raw VM data for {vm_name}: {vm_data}")

            cpu_count = vm_data.get("cpu", {}).get("count", "N/A")
            memory_mb = vm_data.get("memory", {}).get("size_MiB", "N/A")
            memory_gb = round(memory_mb / 1024, 2) if memory_mb != "N/A" else "N/A"
            disk_info = vm_data.get("disks", [])
            total_disk_bytes = sum(disk.get("value", {}).get("capacity", 0) for disk in disk_info)
            disk_gb = round(total_disk_bytes / (1024 * 1024 * 1024), 2)
            guest_os = vm_data.get("guest_OS", "Unknown")

            os_display = "Unknown"
            os_emoji = "❓"
            if "LINUX" in guest_os.upper():
                os_display = "Rocky Linux (64-bit)" if "ROCKY" in guest_os.upper() else "Linux"
                os_emoji = "🐧"
            elif "WINDOWS" in guest_os.upper():
                os_display = "Windows"
                os_emoji = "🪟"

            # Fetch Power Status
            power_url = f"{vcenter_url}/rest/vcenter/vm/{vm_id}/power"
            logger.info(f"Fetching power status from: {power_url}")
            power_response = requests.get(power_url, headers=headers, verify=False)
            power_status = "Powered Off"
            power_emoji = "🔴"
            if power_response.status_code == 200:
                power_data = power_response.json().get("value", {})
                power_state = power_data.get("state", "POWERED_OFF")
                if power_state == "POWERED_ON":
                    power_status = "Powered On"
                    power_emoji = "🟢"
                elif power_state == "SUSPENDED":
                    power_status = "Suspended"
                    power_emoji = "🟡"
            else:
                logger.error(f"Failed to fetch power status for {vm_name}: {power_response.status_code} - {power_response.text}")

            # Fetch VMware Tools Status
            vmware_tools_status = "Not running"
            if power_status == "Powered On":
                guest_url = f"{vcenter_url}/rest/vcenter/vm/{vm_id}/guest/identity"
                logger.info(f"Fetching guest identity from: {guest_url}")
                guest_response = requests.get(guest_url, headers=headers, verify=False)
                if guest_response.status_code == 200:
                    guest_data = guest_response.json().get("value", {})
                    vmware_tools_status = "Running" if guest_data.get("tools_running_status") == "GUEST_TOOLS_RUNNING" else "Not running"
                else:
                    logger.error(f"Failed to fetch guest identity for {vm_name}: {guest_response.status_code} - {guest_response.text}")

            # Fetch Network Info (DNS Name, IP Addresses)
            dns_name = "—"
            ip_addresses = "—"
            if power_status == "Powered On":
                network_url = f"{vcenter_url}/rest/vcenter/vm/{vm_id}/guest/networking/interfaces"
                logger.info(f"Fetching network info from: {network_url}")
                network_response = requests.get(network_url, headers=headers, verify=False)
                if network_response.status_code == 200:
                    interfaces = network_response.json().get("value", [])
                    for interface in interfaces:
                        dns_names = interface.get("dns", {}).get("host_name", "—")
                        if dns_names != "—":
                            dns_name = dns_names
                        ip_list = [ip["ip_address"] for ip in interface.get("ip", {}).get("ip_addresses", []) if ip["ip_address"]]
                        if ip_list:
                            ip_addresses = ", ".join(ip_list)
                else:
                    logger.error(f"Failed to fetch network info for {vm_name}: {network_response.status_code} - {network_response.text}")

            # Fetch Datastore: Parse vmdk_file to extract datastore name
            datastore_display = "Not assigned"
            datastore_ids = set()
            if disk_info:
                for disk in disk_info:
                    disk_value = disk.get("value", {})
                    backing = disk_value.get("backing", {})
                    vmdk_file = backing.get("vmdk_file", "")
                    if vmdk_file:
                        import re
                        match = re.match(r'\[(.*?)\]', vmdk_file)
                        if match:
                            datastore_name = match.group(1)
                            datastore_id = datastore_name_to_id.get(datastore_name)
                            if datastore_id:
                                datastore_ids.add(datastore_id)
                if datastore_ids:
                    datastore_names = [datastore_map.get(ds, "Unknown") for ds in datastore_ids]
                    datastore_display = ", ".join(datastore_names) if datastore_names else "Not assigned"
            logger.info(f"Datastore IDs for VM {vm_name}: {datastore_ids}, Display: {datastore_display}")

            # Fetch Host
            host_id = vm_data.get("host")
            host_name = host_map.get(host_id, "Not assigned")
            logger.info(f"Host ID for VM {vm_name}: {host_id}, Host Name: {host_name}")

            # If host_id is None, infer from host details (similar to /hosts/ endpoint)
            if not host_id and host_details:
                # Find the first host that is powered on and connected
                for host in host_details:
                    if host.get("power_state") == "POWERED_ON" and host.get("connection_state") == "CONNECTED":
                        host_id = host["host"]
                        host_name = host["name"]
                        logger.info(f"Inferred Host for VM {vm_name} from host details (powered on and connected): {host_id}: {host_name}")
                        break
                # If no host is powered on and connected, pick the first host as a fallback
                if not host_id:
                    host_id = host_details[0]["host"]
                    host_name = host_details[0]["name"]
                    logger.info(f"Fallback: Assumed VM {vm_name} is on the first available host: {host_id}: {host_name}")

            # Fetch Cluster
            cluster_id = host_to_cluster_map.get(host_id)
            cluster_name = cluster_map.get(cluster_id, "Not in cluster") if cluster_id else "Not in cluster"
            logger.info(f"Cluster ID for VM {vm_name}: {cluster_id}, Cluster Name: {cluster_name}")

            # Fallback to VMDeployment data if necessary
            if datastore_display == "Not assigned":
                vm_deployment = VMDeployment.objects.filter(vm_name=vm_name).first()
                if vm_deployment:
                    datastore_display = vm_deployment.datastore
                    logger.info(f"Fallback: Using datastore from VMDeployment for {vm_name}: {datastore_display}")

            if cluster_name == "Not in cluster":
                vm_deployment = VMDeployment.objects.filter(vm_name=vm_name).first()
                if vm_deployment:
                    cluster_name = vm_deployment.cluster
                    logger.info(f"Fallback: Using cluster from VMDeployment for {vm_name}: {cluster_name}")

            # If host is still not assigned, infer from the cluster in VMDeployment
            if host_name == "Not assigned" and cluster_name != "Not in cluster":
                cluster_hosts = cluster_to_hosts_map.get(cluster_name, [])
                if cluster_hosts:
                    host_name = cluster_hosts[0]
                    host_id = next((hid for hid, hname in host_map.items() if hname == host_name), None)
                    logger.info(f"Inferred Host for VM {vm_name} from cluster {cluster_name}: {host_name}")

            encryption_status = "Not encrypted"

            vm_details_list.append({
                "name": vm_name,
                "power_status": power_status,
                "power_emoji": power_emoji,
                "os_display": os_display,
                "os_emoji": os_emoji,
                "vmware_tools_status": vmware_tools_status,
                "dns_name": dns_name,
                "ip_addresses": ip_addresses,
                "encryption_status": encryption_status,
                "cpu": cpu_count,
                "cpu_usage": "0",  # Placeholder
                "memory": memory_gb,
                "disk": disk_gb,
                "datastore": datastore_display,
                "cluster": cluster_name,
                "host": host_name
            })
        except Exception as e:
            logger.error(f"Exception while processing VM {vm_name}: {str(e)}")
            continue

    logger.info(f"Returning VM details: {vm_details_list}")
    return render(request, "deploy/partials/vm_summary.html", {"vms": vm_details_list, "vm_name": vm_name})



@csrf_exempt
def launch_remote_console(request, vm_name):
    vcenter_url = request.session.get('vcenter_url')
    vcenter_token = request.session.get('vcenter_token')

    if not vcenter_url or not vcenter_token:
        return JsonResponse({"error": "vCenter authentication required"}, status=403)

    headers = {"vmware-api-session-id": vcenter_token, "Accept": "application/json"}
    vms_url = f"{vcenter_url}/rest/vcenter/vm"
    vms_response = requests.get(vms_url, headers=headers, verify=False)

    if vms_response.status_code != 200:
        logger.error(f"Failed to fetch VMs: {vms_response.status_code} - {vms_response.text}")
        return JsonResponse({"error": f"Failed to fetch VMs: {vms_response.status_code}"}, status=500)

    vms = vms_response.json().get("value", [])
    vm_id = None
    for vm in vms:
        if vm["name"] == vm_name:
            vm_id = vm["vm"]
            break

    if not vm_id:
        logger.error(f"VM {vm_name} not found in vCenter")
        return JsonResponse({"error": "VM not found"}, status=404)

    # Check current power state
    power_url = f"{vcenter_url}/rest/vcenter/vm/{vm_id}/power"
    power_response = requests.get(power_url, headers=headers, verify=False)
    power_state = "Unknown"
    if power_response.status_code == 200:
        power_data = power_response.json().get("value", {})
        power_state = power_data.get("state", "Unknown")
    else:
        logger.error(f"Failed to fetch power state for VM {vm_name}: {power_response.status_code} - {power_response.text}")
        return JsonResponse({"error": f"Failed to fetch power state: {power_response.status_code}"}, status=500)

    # Check if the user intends to convert the VM to a template via the "Launch Web Console" button
    web_console_intent_key = f"web_console_intent_{vm_name}"
    web_console_intent = request.session.get(web_console_intent_key, False)

    if web_console_intent:
        # Clear the web console intent flag
        request.session[web_console_intent_key] = False
        request.session.modified = True
        logger.info(f"Detected web console intent for VM {vm_name}, proceeding with conversion")

        # Check if the VM is powered off (required for conversion to template)
        if power_state != "POWERED_OFF":
            # Set the flag again to retry after powering off
            request.session[web_console_intent_key] = True
            request.session.modified = True
            logger.info(f"VM {vm_name} must be powered off to convert to template")
            return JsonResponse({
                "error": (
                    "VM must be powered off to convert to a template. "
                    "Click the 'Launch Remote Console' button to power off the VM, then set the intent again via /set-web-console-intent/ to convert using the 'Launch Web Console' functionality."
                )
            }, status=400)

        # Convert the VM to a template
        convert_url = f"{vcenter_url}/rest/vcenter/vm/{vm_id}/convert-to-template"
        convert_response = requests.post(convert_url, headers=headers, verify=False)
        if convert_response.status_code in [200, 204]:
            VMActivity.objects.create(
                vm_name=vm_name,
                message=f"{vm_name} - Converted to template via Launch Web Console"
            )
            logger.info(f"VM {vm_name} successfully converted to template")
            # Remove the VM from VMDeployment since it's now a template
            VMDeployment.objects.filter(vm_name=vm_name).delete()
            return JsonResponse({
                "error": (
                    "VM has been successfully converted to a template using the 'Launch Web Console' functionality. "
                    "It will no longer appear in the VM list.\n\n"
                    "Click the 'Launch Remote Console' button to resume normal operations (launch remote console, power off, power on)."
                )
            })
        else:
            logger.error(f"Failed to convert VM {vm_name} to template: {convert_response.status_code} - {convert_response.text}")
            return JsonResponse({
                "error": f"Failed to convert VM to template using 'Launch Web Console': {convert_response.status_code} - {convert_response.text}"
            }, status=500)

    # If no web console intent, proceed with the normal action cycle
    session_key = f"last_action_{vm_name}"
    last_action = request.session.get(session_key, "none")
    logger.info(f"Last action for VM {vm_name}: {last_action}")

    # Define the action cycle: none -> rdp -> power_off -> power_on -> rdp
    actions_cycle = ["rdp", "power_off", "power_on"]
    current_action_index = actions_cycle.index(last_action) if last_action in actions_cycle else -1
    next_action_index = (current_action_index + 1) % len(actions_cycle)
    current_action = actions_cycle[next_action_index]

    # Store the current action in the session
    request.session[session_key] = current_action
    request.session.modified = True
    logger.info(f"Current action for VM {vm_name}: {current_action}")

    # Perform the current action
    if current_action == "rdp":
        if power_state != "POWERED_ON":
            request.session[session_key] = "power_on"
            request.session.modified = True
            logger.info(f"VM {vm_name} is not powered on, setting next action to power_on")
            return JsonResponse({
                "error": "VM must be powered on to launch remote console. Click the button again to power on the VM."
            }, status=400)

        network_url = f"{vcenter_url}/rest/vcenter/vm/{vm_id}/guest/networking/interfaces"
        network_response = requests.get(network_url, headers=headers, verify=False)
        ip_address = None
        if network_response.status_code == 200:
            interfaces = network_response.json().get("value", [])
            for interface in interfaces:
                ip_list = [ip["ip_address"] for ip in interface.get("ip", {}).get("ip_addresses", []) if ip["ip_address"]]
                if ip_list:
                    ip_address = ip_list[0]
                    break
        else:
            logger.error(f"Failed to fetch network info for VM {vm_name}: {network_response.status_code} - {network_response.text}")
            return JsonResponse({"error": f"Failed to fetch network info: {network_response.status_code}"}, status=500)

        if not ip_address:
            logger.error(f"No IP address found for VM {vm_name}")
            return JsonResponse({"error": "No IP address found for the VM"}, status=400)

        VMActivity.objects.create(
            vm_name=vm_name,
            message=f"{vm_name} - Attempted to launch RDP console"
        )
        return JsonResponse({
            "error": (
                f"Please launch RDP manually using this IP: {ip_address}. On Windows, press Win+R, type 'mstsc', and enter this IP.\n\n"
                "Click the button again to power off the VM."
            )
        })

    elif current_action == "power_off":
        if power_state == "POWERED_OFF":
            request.session[session_key] = "power_on"
            request.session.modified = True
            logger.info(f"VM {vm_name} is already powered off, setting next action to power_on")
            return JsonResponse({
                "error": "VM is already powered off. Click the button again to power on the VM."
            })

        power_off_url = f"{vcenter_url}/rest/vcenter/vm/{vm_id}/power/stop"
        power_off_response = requests.post(power_off_url, headers=headers, verify=False)
        if power_off_response.status_code in [200, 204]:
            VMActivity.objects.create(
                vm_name=vm_name,
                message=f"{vm_name} - Powered off"
            )
            logger.info(f"VM {vm_name} successfully powered off")
            return JsonResponse({
                "error": "VM has been powered off. Click the button again to power on the VM."
            })
        else:
            logger.error(f"Failed to power off VM {vm_name}: {power_off_response.status_code} - {power_off_response.text}")
            return JsonResponse({"error": f"Failed to power off VM: {power_off_response.status_code} - {power_off_response.text}"}, status=500)

    elif current_action == "power_on":
        if power_state == "POWERED_ON":
            request.session[session_key] = "rdp"
            request.session.modified = True
            logger.info(f"VM {vm_name} is already powered on, setting next action to rdp")
            return JsonResponse({
                "error": "VM is already powered on. Click the button again to launch the remote console."
            })

        power_on_url = f"{vcenter_url}/rest/vcenter/vm/{vm_id}/power/start"
        power_on_response = requests.post(power_on_url, headers=headers, verify=False)
        if power_on_response.status_code in [200, 204]:
            VMActivity.objects.create(
                vm_name=vm_name,
                message=f"{vm_name} - Powered on"
            )
            logger.info(f"VM {vm_name} successfully powered on")
            return JsonResponse({
                "error": "VM has been powered on. Click the button again to launch the remote console."
            })
        else:
            logger.error(f"Failed to power on VM {vm_name}: {power_on_response.status_code} - {power_on_response.text}")
            return JsonResponse({"error": f"Failed to power on VM: {power_on_response.status_code} - {power_on_response.text}"}, status=500)

    logger.error(f"Unknown action for VM {vm_name}: {current_action}")
    return JsonResponse({"error": "Unknown action"}, status=500)
     


@csrf_exempt
def power_on_vm(request, vm_name):
    """Power on the specified VM with retry mechanism."""
    vcenter_url = request.session.get('vcenter_url')
    vcenter_token = request.session.get('vcenter_token')

    logger.info(f"Attempting to power on VM: {vm_name}")
    if not vcenter_url or not vcenter_token:
        logger.error("vCenter authentication required")
        return JsonResponse({"error": "vCenter authentication required"}, status=403)

    headers = {"vmware-api-session-id": vcenter_token, "Accept": "application/json"}
    vms_url = f"{vcenter_url}/rest/vcenter/vm"
    max_retries = 3
    retry_delay = 5  # seconds

    for attempt in range(max_retries):
        try:
            logger.debug(f"Fetching VM list (attempt {attempt + 1}): {vms_url}")
            vms_response = requests.get(vms_url, headers=headers, verify=False)
            if vms_response.status_code != 200:
                logger.error(f"Failed to fetch VMs: {vms_response.status_code} - {vms_response.text}")
                if vms_response.status_code == 503 and attempt < max_retries - 1:
                    logger.info(f"Retrying after {retry_delay} seconds due to 503 error")
                    time.sleep(retry_delay)
                    continue
                return JsonResponse({"error": f"Failed to fetch VMs: {vms_response.status_code}"}, status=500)

            vms = vms_response.json().get("value", [])
            vm_id = None
            for vm in vms:
                if vm["name"] == vm_name:
                    vm_id = vm["vm"]
                    break

            if not vm_id:
                logger.error(f"VM {vm_name} not found")
                return JsonResponse({"error": "VM not found"}, status=404)

            power_url = f"{vcenter_url}/rest/vcenter/vm/{vm_id}/power"
            logger.debug(f"Fetching power state for VM {vm_name}: {power_url}")
            power_response = requests.get(power_url, headers=headers, verify=False)
            if power_response.status_code != 200:
                logger.error(f"Failed to fetch power state for VM {vm_name}: {power_response.status_code}")
                if power_response.status_code == 503 and attempt < max_retries - 1:
                    logger.info(f"Retrying after {retry_delay} seconds due to 503 error")
                    time.sleep(retry_delay)
                    continue
                return JsonResponse({"error": "Failed to fetch power state"}, status=500)

            power_data = power_response.json().get("value", {})
            power_state = power_data.get("state", "UNKNOWN")
            logger.debug(f"Current power state for VM {vm_name}: {power_state}")

            if power_state == "POWERED_ON":
                logger.info(f"VM {vm_name} is already powered on")
                return JsonResponse({"message": f"VM {vm_name} is already powered on"})
            elif power_state in ["POWERED_OFF", "SUSPENDED"]:
                power_on_url = f"{vcenter_url}/rest/vcenter/vm/{vm_id}/power/start"
                logger.debug(f"Powering on VM {vm_name}: {power_on_url}")
                power_on_response = requests.post(power_on_url, headers=headers, verify=False)
                if power_on_response.status_code in [200, 204]:
                    VMActivity.objects.create(vm_name=vm_name, message=f"{vm_name} - Powered on")
                    logger.info(f"VM {vm_name} powered on successfully")
                    return JsonResponse({"message": f"VM {vm_name} has been powered on"})
                else:
                    logger.error(f"Failed to power on VM {vm_name}: {power_on_response.status_code} - {power_on_response.text}")
                    if power_on_response.status_code == 503 and attempt < max_retries - 1:
                        logger.info(f"Retrying after {retry_delay} seconds due to 503 error")
                        time.sleep(retry_delay)
                        continue
                    return JsonResponse({"error": f"Failed to power on VM: {power_on_response.status_code} - {power_on_response.text}"}, status=500)
            else:
                logger.error(f"Unexpected power state for VM {vm_name}: {power_state}")
                return JsonResponse({"error": f"VM {vm_name} is in an unexpected state: {power_state}"}, status=400)
        except Exception as e:
            logger.error(f"Error in power_on_vm for {vm_name} (attempt {attempt + 1}): {str(e)}")
            if attempt < max_retries - 1:
                logger.info(f"Retrying after {retry_delay} seconds due to exception")
                time.sleep(retry_delay)
                continue
            return JsonResponse({"error": f"Server error: {str(e)}"}, status=500)

    logger.error(f"Failed to power on VM {vm_name} after {max_retries} attempts")
    return JsonResponse({"error": f"Failed to power on VM after {max_retries} attempts"}, status=500)
@csrf_exempt
def power_off_vm(request, vm_name):
    """Power off the specified VM."""
    vcenter_url = request.session.get('vcenter_url')
    vcenter_token = request.session.get('vcenter_token')

    if not vcenter_url or not vcenter_token:
        logger.error("vCenter authentication required")
        return JsonResponse({"error": "vCenter authentication required"}, status=403)

    headers = {"vmware-api-session-id": vcenter_token, "Accept": "application/json"}
    vms_url = f"{vcenter_url}/rest/vcenter/vm"
    try:
        vms_response = requests.get(vms_url, headers=headers, verify=False)
        if vms_response.status_code != 200:
            logger.error(f"Failed to fetch VMs: {vms_response.status_code} - {vms_response.text}")
            return JsonResponse({"error": f"Failed to fetch VMs: {vms_response.status_code}"}, status=500)

        vms = vms_response.json().get("value", [])
        vm_id = None
        for vm in vms:
            if vm["name"] == vm_name:
                vm_id = vm["vm"]
                break

        if not vm_id:
            logger.error(f"VM {vm_name} not found")
            return JsonResponse({"error": "VM not found"}, status=404)

        power_url = f"{vcenter_url}/rest/vcenter/vm/{vm_id}/power"
        power_response = requests.get(power_url, headers=headers, verify=False)
        if power_response.status_code != 200:
            logger.error(f"Failed to fetch power state for VM {vm_name}: {power_response.status_code}")
            return JsonResponse({"error": "Failed to fetch power state"}, status=500)

        power_data = power_response.json().get("value", {})
        power_state = power_data.get("state", "UNKNOWN")
        if power_state == "POWERED_OFF":
            return JsonResponse({"message": f"VM {vm_name} is already powered off"})
        elif power_state == "POWERED_ON":
            power_off_url = f"{vcenter_url}/rest/vcenter/vm/{vm_id}/power/stop"
            power_off_response = requests.post(power_off_url, headers=headers, verify=False)
            if power_off_response.status_code in [200, 204]:
                VMActivity.objects.create(vm_name=vm_name, message=f"{vm_name} - Powered off")
                logger.info(f"VM {vm_name} powered off successfully")
                return JsonResponse({"message": f"VM {vm_name} has been powered off"})
            else:
                logger.error(f"Failed to power off VM {vm_name}: {power_off_response.status_code} - {power_off_response.text}")
                return JsonResponse({"error": f"Failed to power off VM: {power_off_response.status_code}"}, status=500)
        else:
            logger.error(f"Unexpected power state for VM {vm_name}: {power_state}")
            return JsonResponse({"error": f"VM {vm_name} is in an unexpected state: {power_state}"}, status=400)
    except Exception as e:
        logger.error(f"Error in power_off_vm for {vm_name}: {str(e)}")
        return JsonResponse({"error": f"Server error: {str(e)}"}, status=500)

@csrf_exempt
def convert_to_template(request, vm_name):
    vcenter_url = request.session.get('vcenter_url')
    vcenter_token = request.session.get('vcenter_token')
    logger.info(f"Session data - vcenter_url: {vcenter_url}, vcenter_token: {vcenter_token}")

    if not vcenter_url or not vcenter_token:
        logger.error("vCenter authentication required - session data missing")
        return JsonResponse({"error": "vCenter authentication required"}, status=403)
        
    headers = {"vmware-api-session-id": vcenter_token, "Accept": "application/json"}
    vms_url = f"{vcenter_url}/rest/vcenter/vm"
    vms_response = requests.get(vms_url, headers=headers, verify=False)

    if vms_response.status_code != 200:
        logger.error(f"Failed to fetch VMs: {vms_response.status_code} - {vms_response.text}")
        return JsonResponse({"error": f"Failed to fetch VMs: {vms_response.status_code}"}, status=500)

    vms = vms_response.json().get("value", [])
    vm_id = None
    for vm in vms:
        if vm["name"] == vm_name:
            vm_id = vm["vm"]
            break

    if not vm_id:
        logger.error(f"VM {vm_name} not found in vCenter")
        return JsonResponse({"error": "VM not found"}, status=404)

    # Check current power state
    power_url = f"{vcenter_url}/rest/vcenter/vm/{vm_id}/power"
    power_response = requests.get(power_url, headers=headers, verify=False)
    power_state = "Unknown"
    if power_response.status_code == 200:
        power_data = power_response.json().get("value", {})
        power_state = power_data.get("state", "Unknown")
    else:
        logger.error(f"Failed to fetch power state for VM {vm_name}: {power_response.status_code} - {power_response.text}")
        return JsonResponse({"error": f"Failed to fetch power state: {power_response.status_code}"}, status=500)

    # Check if the VM is powered off (required for conversion to template)
    if power_state != "POWERED_OFF":
        logger.info(f"VM {vm_name} must be powered off to convert to template")
        return JsonResponse({
            "error": (
                "VM must be powered off to convert to a template. "
                "Please power off the VM using the 'Launch Remote Console' button and try again."
            )
        }, status=400)

    # Convert the VM to a template
    convert_url = f"{vcenter_url}/rest/vcenter/vm/{vm_id}/convert-to-template"
    convert_response = requests.post(convert_url, headers=headers, verify=False)
    if convert_response.status_code in [200, 204]:
        VMActivity.objects.create(
            vm_name=vm_name,
            message=f"{vm_name} - Converted to template"
        )
        logger.info(f"VM {vm_name} successfully converted to template")
        # Remove the VM from VMDeployment since it's now a template
        VMDeployment.objects.filter(vm_name=vm_name).delete()
        return JsonResponse({
            "message": (
                "VM has been successfully converted to a template. "
                "It will no longer appear in the VM list."
            )
        })
    else:
        logger.error(f"Failed to convert VM {vm_name} to template: {convert_response.status_code} - {convert_response.text}")
        return JsonResponse({
            "error": f"Failed to convert VM to template: {convert_response.status_code} - {convert_response.text}"
        }, status=500)



@csrf_exempt
def vm_new_list_view(request):
    return render(request, 'deploy/vm_new_list.html')

def vm_distribution(request):
    try:
        # Retrieve vCenter credentials from session
        vcenter_url = request.session.get('vcenter_url')
        vcenter_token = request.session.get('vcenter_token')
        username = request.session.get('vcenter_username')
        password = request.session.get('vcenter_password')

        if not vcenter_url or not username or not password:
            logger.error("vCenter authentication required: URL, username, or password missing")
            return redirect("login_page")

        # Authenticate with vCenter if no token exists
        if not vcenter_token:
            auth_url = f"{vcenter_url}/rest/com/vmware/cis/session"
            session_response = requests.post(auth_url, auth=(username, password), verify=False)
            if session_response.status_code != 200:
                logger.error(f"Failed to authenticate with vCenter: {session_response.status_code} - {session_response.text}")
                raise Exception("Failed to authenticate with vCenter")
            vcenter_token = session_response.json()['value']
            request.session['vcenter_token'] = vcenter_token
            request.session.modified = True
            logger.info("Successfully authenticated with vCenter and stored token in session")

        # Fetch VMs
        headers = {"vmware-api-session-id": vcenter_token}
        response = requests.get(f"{vcenter_url}/rest/vcenter/vm", headers=headers, verify=False)
        if response.status_code != 200:
            if response.status_code == 401:  # Token might have expired
                logger.warning("vCenter token expired, re-authenticating")
                auth_url = f"{vcenter_url}/rest/com/vmware/cis/session"
                session_response = requests.post(auth_url, auth=(username, password), verify=False)
                if session_response.status_code != 200:
                    logger.error(f"Failed to re-authenticate with vCenter: {session_response.status_code} - {session_response.text}")
                    raise Exception("Failed to re-authenticate with vCenter")
                vcenter_token = session_response.json()['value']
                request.session['vcenter_token'] = vcenter_token
                request.session.modified = True
                headers = {"vmware-api-session-id": vcenter_token}
                response = requests.get(f"{vcenter_url}/rest/vcenter/vm", headers=headers, verify=False)
                if response.status_code != 200:
                    logger.error(f"Failed to fetch VMs from vCenter after re-authentication: {response.status_code} - {response.text}")
                    raise Exception("Failed to fetch VMs from vCenter after re-authentication")
            else:
                logger.error(f"Failed to fetch VMs from vCenter: {response.status_code} - {response.text}")
                raise Exception("Failed to fetch VMs from vCenter")

        vms = response.json()['value']
        logger.info(f"Total VMs fetched: {len(vms)}")

        # Fetch guest OS details for each VM and collect names
        linux_vms = []
        windows_vms = []
        others = []

        for vm in vms:
            try:
                vm_id = vm['vm']
                vm_name = vm.get('name', 'Unknown').lower()

                # Skip vCLS VMs
                if vm_name.startswith('vcls-'):
                    logger.info(f"Skipping vCLS VM: {vm_name}")
                    continue

                # Try the guest_OS field first
                os = vm.get('guest_OS', '').lower()
                logger.info(f"VM: {vm_name}, Guest OS from /vm: {os}")

                # If guest_OS is empty, fetch from /guest/identity
                if not os:
                    guest_response = requests.get(
                        f"{vcenter_url}/rest/vcenter/vm/{vm_id}/guest/identity",
                        headers=headers,
                        verify=False
                    )
                    if guest_response.status_code == 200:
                        guest_info = guest_response.json()['value']
                        os = guest_info.get('name', '').lower()
                        logger.info(f"VM: {vm_name}, Guest OS from /guest/identity: {os}")
                    else:
                        logger.warning(f"Failed to fetch guest identity for VM {vm_name}: {guest_response.status_code} - {guest_response.text}")
                        os = ''

                # Fallback to VM name if OS is still empty
                if not os:
                    os = vm_name
                    logger.info(f"VM: {vm_name}, Using VM name as OS fallback: {os}")

                # Define vm_details dictionary
                vm_details = {
                    'name': vm_name,
                    'os': os
                }

                # Categorize the VM with expanded keywords for Linux
                linux_keywords = [
                    'linux', 'rhel', 'centos', 'ubuntu', 'debian', 'suse', 'fedora', 'oracle linux',
                    'rocky', 'photon', 'amazon linux', 'almalinux', 'miracle linux', 'asianux',
                    'red hat', 'redhat', 'jayanth', 'test 3', 'test3', 'skrishna6', 'ps24', 'coevro',
                    'coead','prtg-vyos','coensx','sample','test_vm_cn4_l','pratusha'
                ]

                windows_keywords = [
                    'windows', 'win2k', 'win10', 'desktop-', 'win-', 'microsoft', 'ms-dos', 'win19',
                    'w2019', 'windows2022','va9_win','prtg-win','vijay_win','win_1','anakage','demomachine','test_vm_cn4', 'awx deploy','skrishna6','Skrishna6_1','test_vm_cn4'
                ]

                if any(keyword in os for keyword in linux_keywords):
                    linux_vms.append(vm_details)
                    logger.info(f"VM: {vm_name} categorized as Linux, OS: {os}")
                elif any(keyword in os for keyword in windows_keywords):
                    windows_vms.append(vm_details)
                    logger.info(f"VM: {vm_name} categorized as Windows, OS: {os}")
                else:
                    others.append(vm_details)
                    logger.debug(f"VM: {vm_name} categorized as Others, OS: {os}, VM Name: {vm_name}")

            except Exception as e:
                logger.error(f"Error processing VM {vm_name}: {str(e)}")
                continue  # Skip this VM and continue with the next one

        logger.info(f"VM Distribution - Linux: {len(linux_vms)}, Windows: {len(windows_vms)}, Others: {len(others)}")

        # Join the VM names into a comma-separated string for each category
        linux_vm_names = ','.join(vm['name'] for vm in linux_vms)
        windows_vm_names = ','.join(vm['name'] for vm in windows_vms)
        other_vm_names = ','.join(vm['name'] for vm in others)

        # Return HTML with data attributes for HTMX
        return HttpResponse(
            f'<div id="vm-distribution-data" data-linux-vms="{len(linux_vms)}" '
            f'data-windows-vms="{len(windows_vms)}" data-others="{len(others)}" '
            f'data-linux-vm-names="{linux_vm_names}" '
            f'data-windows-vm-names="{windows_vm_names}" '
            f'data-other-vm-names="{other_vm_names}"></div>'
        )

    except Exception as e:
        logger.error(f"Error fetching VM distribution: {str(e)}")
        return HttpResponse(
            '<div id="vm-distribution-data" data-linux-vms="0" '
            'data-windows-vms="0" data-others="0" '
            'data-linux-vm-names="" '
            'data-windows-vm-names="" '
            'data-other-vm-names=""></div>'
        )

def vm_category_list(request, category):
    """Render VMs of a specific category in a table format."""
    if 'vcenter_token' not in request.session:
        return redirect("login_page")

    # Define vcenter_url and headers
    vcenter_url = request.session.get('vcenter_url')
    headers = {
        'vmware-api-session-id': request.session.get('vcenter_token'),
        'Content-Type': 'application/json'
    }

    # Fetch all VMs and categorize them
    vms = get_vms(request)
    if isinstance(vms, HttpResponseRedirect):  # Handle redirect from get_vms
        return vms

    logger.info(f"Fetched VMs: {vms}")
    linux_vms = []
    windows_vms = []
    other_vms = []

    for vm in vms:
        try:
            logger.info(f"Processing VM: {vm}")
            vm_id = vm['vm']
            original_vm_name = vm.get('name', 'Unknown')  # Preserve original case
            vm_name = original_vm_name.lower()  # Lowercase for categorization

            # Skip vCLS VMs
            if vm_name.startswith('vcls-'):
                logger.info(f"Skipping vCLS VM: {vm_name}")
                continue

            # Try the guest_OS field first
            os = vm.get('guest_OS', '').lower()
            logger.info(f"VM: {vm_name}, Guest OS from /vm: {os}")

            # If guest_OS is empty, fetch from /guest/identity
            if not os:
                guest_response = requests.get(
                    f"{vcenter_url}/rest/vcenter/vm/{vm_id}/guest/identity",
                    headers=headers,
                    verify=False
                )
                if guest_response.status_code == 200:
                    guest_info = guest_response.json()['value']
                    os = guest_info.get('name', '').lower()
                    logger.info(f"VM: {vm_name}, Guest OS from /guest/identity: {os}")
                else:
                    logger.warning(f"Failed to fetch guest identity for VM {vm_name}: {guest_response.status_code} - {guest_response.text}")
                    os = ''

            # Fallback to VM name if OS is still empty
            if not os:
                os = vm_name
                logger.info(f"VM: {vm_name}, Using VM name as OS fallback: {os}")

            # Log the final OS used for categorization
            logger.info(f"VM: {vm_name}, Final OS for categorization: {os}")

            # Define vm_details dictionary
            vm_details = {
                'name': original_vm_name,  # Use original case for display and get_vm_details
                'os': os
            }

            # Categorize the VM with expanded keywords for Linux
            linux_keywords = [
                'linux', 'rhel', 'centos', 'ubuntu', 'debian', 'suse', 'fedora', 'oracle linux',
                'rocky', 'photon', 'amazon linux', 'almalinux', 'miracle linux', 'asianux',
                'red hat', 'redhat', 'jayanth', 'test 3', 'test3', 'skrishna6', 'ps24', 'coevro',
                'coead', 'prtg-vyos', 'coensx', 'sample', 'test_vm_cn4_l',  'pratusha'
            ]

            windows_keywords = [
                'windows', 'win2k', 'win10', 'desktop-', 'win-', 'microsoft', 'ms-dos', 'win19',
                'w2019', 'windows2022', 'va9_win', 'prtg-win', 'vijay_win', 'win_1', 'anakage', 'demomachine', 'test_vm_cn4',
                'windows_9_64', 'windows_9', 'win_9_64', 'win_9', 'windows_server_2019', 'awx deploy','skrishna6','Skrishna6_1','test_vm_cn4'  # Added variations
            ]

            if any(keyword in os for keyword in linux_keywords):
                linux_vms.append(vm_details)
                logger.info(f"VM: {vm_name} categorized as Linux, OS: {os}")
            elif any(keyword in os for keyword in windows_keywords):
                windows_vms.append(vm_details)
                logger.info(f"VM: {vm_name} categorized as Windows, OS: {os}")
            else:
                other_vms.append(vm_details)
                logger.debug(f"VM: {vm_name} categorized as Others, OS: {os}, VM Name: {original_vm_name}")

        except Exception as e:
            logger.error(f"Error processing VM: {str(e)}")
            continue  # Skip this VM and continue with the next one

    # Log the VM distribution after the loop
    logger.info(f"VM Distribution - Linux: {len(linux_vms)}, Windows: {len(windows_vms)}, Others: {len(other_vms)}")
    logger.info(f"Windows VMs: {[vm['name'] for vm in windows_vms]}")

    # Select the VM names based on the category
    vm_names = []
    if category.lower() == 'linux':
        vm_names = linux_vms
    elif category.lower() == 'windows':
        vm_names = windows_vms
    elif category.lower() == 'others':
        vm_names = other_vms

    logger.info(f"Selected VMs for category '{category}': {[vm['name'] for vm in vm_names]}")

    # Fetch detailed VM information for each VM name
    vms = []
    for vm_details in vm_names:
        if vm_details:
            vm_detail = get_vm_details(request, vm_details['name'])
            logger.info(f"VM Details for {vm_details['name']}: {vm_detail}")
            if isinstance(vm_detail, list) and vm_detail:
                vms.append(vm_detail[0])

    logger.info(f"Final VMs to render: {[vm['name'] for vm in vms]}")

    # Capitalize the category for display (e.g., 'linux' -> 'Linux')
    category_display = category.capitalize()

    return render(request, "deploy/vm_category_list.html", {
        "vms": vms,
        "category": category_display
    })



