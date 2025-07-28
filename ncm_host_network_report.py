#!/usr/bin/env python3
"""
===============================================================================
 Script Name   : ncm_report_vm_network.py
 Description   : Generates VM Network Inventory Report
 Author        : Amit Yadav
 Created Date  : [2025-07-24]
 Last Modified : [YYYY-MM-DD]
 Version       : [v1.0.0]
 Usage         : python ncm_report_vm_network.py --pc_ip <IP> --pc_user admin --pc_secret <secret> --output_path "/home/rocky" --output_files_name <filename>
 Dependencies  : pip install python-csv argparse requests datetime urllib3 tabulate pathlib 
                pip install ntnx_vmm_py_client ntnx_clustermgmt_py_client ntnx_prism_py_client

===============================================================================
"""


import datetime
import argparse
# import getpass
import csv
# from tabulate import tabulate
from pathlib import Path
import pprint
import urllib3  # type: ignore
import json
import requests

pc_name = ""
current_time = datetime.datetime.now(datetime.timezone.utc)  # Use timezone-aware UTC datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from ntnx_clustermgmt_py_client import ApiClient as ClusterMgmtClient  # type: ignore
from ntnx_clustermgmt_py_client import Configuration as ClusterMgmtConfiguration  # type: ignore
from ntnx_clustermgmt_py_client.rest import ApiException as ClusterMgmtException  # type: ignore
from ntnx_clustermgmt_py_client.api import ClustersApi


from ntnx_networking_py_client import Configuration as NetworkingConfiguration  # type: ignore
from ntnx_networking_py_client import ApiClient as NetworkingApiClient  # type: ignore
from ntnx_networking_py_client.api import VirtualSwitchesApi, SubnetsApi  # type: ignore

# variables to Fetch
# SWITCH_NAME = "" #switch vendor info
SWITCH_MAC_ADDRESS = ""
SWITCH_IP = ""  # check ipv4 if not then ipv6
SWITCH_PORT_NIC = "" # attached_switch_interface_list
VIRTUAL_SWITCH = ""
BOND_POLICY = ""
CLUSTER = ""
PC = ""
HOST_SERIAL_NUMBER = ""

def initialize_clustermgmt_api(api_server, username, password):
    """Initialize and return the ClustersApi client."""
    configuration = ClusterMgmtConfiguration()
    configuration.host = api_server
    configuration.username = username
    configuration.password = password
    configuration.verify_ssl = False
    api_client = ClusterMgmtClient(configuration=configuration)
    return ClustersApi(api_client)

def initialize_networking_api(api_server, username, password):
    """Initialize and return the Nutanix networking API clients."""
    configuration = NetworkingConfiguration()
    configuration.host = api_server
    configuration.username = username
    configuration.password = password
    configuration.verify_ssl = False
    api_client = NetworkingApiClient(configuration=configuration)
    return {
        "virtual_switches": VirtualSwitchesApi(api_client),
        "subnets": SubnetsApi(api_client)
    }

def get_cluster_ext_map(clusters_api,cluster_names):
    """Return a mapping of cluster names to extIds from the clusters API."""
    global pc_name
    clusters = clusters_api.list_clusters().to_dict()
    # print(clusters)
    cluster_ext_map = {}
    for cluster in clusters['data']:
        if cluster['config']['cluster_function'][0] == "PRISM_CENTRAL":
            pc_name = cluster['name']
        elif (cluster['name'] in cluster_names) or  (cluster_names[0] == "ALL"):
            cluster_ext_map[cluster['name']] = cluster['ext_id']
    return cluster_ext_map

def get_hosts_by_cluster(clusters_api, cluster_ext_id):
    """Fetch hosts by cluster ext_id."""
    try:
        hosts = clusters_api.list_hosts_by_cluster_id(clusterExtId=cluster_ext_id, _limit=100).to_dict()
        # print(hosts)
        return hosts['data'] if 'data' in hosts else []
    except ClusterMgmtException as e:
        print(f"[ERROR] Failed to fetch hosts for cluster {cluster_ext_id}: {e}")
        return []

def get_pc_name(clusters_api):
    """Fetch and return the name of the Prism Central."""
    clusters = clusters_api.list_clusters().to_dict()
    # print(clusters)
    cluster_ext_map = {}
    for cluster in clusters['data']:
        if cluster['config']['cluster_function'][0] == "PRISM_CENTRAL":
            return cluster['name']
    return ""

def get_virtual_switches(virtual_switches_api):
    """Fetch and return a mapping of virtual switch ext_ids to names."""
    try:
        virtual_switches = virtual_switches_api.list_virtual_switches(_limit=100).to_dict()
        print(virtual_switches)
        vs_map = {vs['ext_id']: vs['name'] for vs in virtual_switches['data']}
        return vs_map
    except Exception as e:
        print(f"[ERROR] Failed to fetch virtual switches: {e}")
        return {}

def get_host_nic_by_host_id(clusters_api, clusterExtId, host_ext_id):
    """Fetch NICs for a given host by its ext_id."""
    try:
        host = clusters_api.list_host_nics_by_host_id(clusterExtId=clusterExtId, hostExtId=host_ext_id).to_dict()
        print(json.dumps(host, indent=2))
        exit()
        nics = host.get('nics', [])
        return nics
    except ClusterMgmtException as e:
        print(f"[ERROR] Failed to fetch NICs for host {host_ext_id}: {e}")
        return []

def get_hosts_by_clusters(clusters_api, cluster_ext_map):
    """Return a dict mapping cluster_ext_id to {host_ext_id: host_name}."""
    cluster_hosts = {}
    for cluster_name, cluster_ext_id in cluster_ext_map.items():
        try:
            hosts = clusters_api.list_hosts_by_cluster_id(clusterExtId=cluster_ext_id, _limit=100).to_dict()
            hosts_data = hosts.get('data', [])
            host_map = {host.get('ext_id', 'Unknown'): host.get('host_name', 'Unknown') for host in hosts_data}
            cluster_hosts[cluster_ext_id] = host_map
        except ClusterMgmtException as e:
            print(f"[ERROR] Failed to fetch hosts for cluster {cluster_ext_id}: {e}")
            cluster_hosts[cluster_ext_id] = {}
    return cluster_hosts

def get_virtual_nic_by_host_id(clusters_api, cluster_ext_id, host_ext_id):
    """Fetch virtual NICs for a given host by its ext_id."""
    try:
        nics = clusters_api.list_host_nics_by_host_id(clusterExtId=cluster_ext_id, hostExtId=host_ext_id).to_dict()
        return nics.get('data', [])
    except ClusterMgmtException as e:
        print(f"[ERROR] Failed to fetch virtual NICs for host {host_ext_id}: {e}")
        return []

def get_virtual_nic_by_id(clusters_api, cluster_ext_id, host_ext_id):
    """Fetch virtual NICs for a given host by its ext_id."""
    try:
        nics = clusters_api.get_host_nic_by_id(clusterExtId=cluster_ext_id, hostExtId=host_ext_id, extId="f28effad-0c3b-4a76-8248-f69c51ca15ba").to_dict()
        return nics.get('data', [])
    except ClusterMgmtException as e:
        print(f"[ERROR] Failed to fetch virtual NICs for host {host_ext_id}: {e}")
        return []
    
def get_serial_no_by_cluster_host(cluster_ext_id, host_ext_id, pc_ip, pc_user, pc_secret):
    """Fetch serial number for a given host by its ext_id."""
    


def fetch_host_details(cluster_ext_id, pc_ip, pc_user, pc_secret):
    url = f"https://{pc_ip}:9440/PrismGateway/services/rest/v1/hosts?proxyClusterUuid={cluster_ext_id}"
    headers = {"Content-Type": "application/json"}
    response = requests.get(url, headers=headers, auth=(pc_user, pc_secret), verify=False)
    response.raise_for_status()
    data = response.json()
    host_map = {}
    for host in data.get("entities", []):
        ext_id = host.get("uuid", "")
        host_map[ext_id] = {
            "name": host.get("name", "Unknown"),
            "ip": host.get("serviceVMExternalIP", ""),
            "serial": host.get("serial", "")
        }
    return host_map

def fetch_switch_details(cluster_ext_id, pc_ip, pc_user, pc_secret):
    url = f"https://{pc_ip}:9440/PrismGateway/services/rest/v1/switches?proxyClusterUuid={cluster_ext_id}"
    headers = {"Content-Type": "application/json"}
    try:
        response = requests.get(url, headers=headers, auth=(pc_user, pc_secret), verify=False, timeout=10)
        response.raise_for_status()
        data = response.json()
        if isinstance(data, list) and data:
            switch = data[0]
            switch_name = switch.get("name", "")
            switch_ips = switch.get("managementAddresses", [])
            switch_ip = switch_ips[0] if switch_ips else ""
            return switch_name, switch_ip
    except Exception as e:
        print(f"[WARN] Could not fetch switch details for cluster {cluster_ext_id}: {e}")
    return "", ""

def write_virtual_switches_csv(virtual_switches, pc_name, cluster_ext_map, cluster_hosts, host_details_map, switch_details_map, output_path):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d-%H-%M-%S')
    csv_file = Path(output_path) / f"PC_{pc_name}_host_network_report_{timestamp}.csv"
    with open(csv_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["pc_name", "cluster_name", "host_name", "host_ip", "host_serial_no", "virtual_switch", "host_interfaces", "bond_mode", "switch_name", "switch_ip"])
        for vs in virtual_switches.get("data", []):
            vs_name = vs.get("name", "")
            if vs_name == "no_uplink":
                continue
            bond_mode = vs.get("bond_mode", "")
            for cluster in vs.get("clusters", []):
                cluster_ext_id = cluster.get("ext_id", "")
                cluster_name = next((name for name, ext in cluster_ext_map.items() if ext == cluster_ext_id), cluster_ext_id)
                hosts_map = cluster_hosts.get(cluster_ext_id, {})
                host_details = host_details_map.get(cluster_ext_id, {})
                switch_name, switch_ip = switch_details_map.get(cluster_ext_id, ("", ""))
                for host in cluster.get("hosts", []):
                    host_ext_id = host.get("ext_id", "")
                    details = host_details.get(host_ext_id, {})
                    host_name = details.get("name", hosts_map.get(host_ext_id, "Unknown"))
                    host_ip = details.get("ip", "")
                    host_serial = details.get("serial", "")
                    host_nics = host.get("host_nics", [])
                    if not host_nics:
                        writer.writerow([pc_name, cluster_name, host_name, host_ip, host_serial, vs_name, "", bond_mode, switch_name, switch_ip])
                    else:
                        for iface in host_nics:
                            writer.writerow([pc_name, cluster_name, host_name, host_ip, host_serial, vs_name, iface, bond_mode, switch_name, switch_ip])
    print(f"Output file created: {csv_file}")

def get_virtual_switches_data(virtual_switches, pc_name, cluster_ext_map, cluster_hosts, host_details_map, switch_details_map):
    """
    Gather virtual switch data as a list of dicts for CSV writing.
    """
    rows = []
    for vs in virtual_switches.get("data", []):
        vs_name = vs.get("name", "")
        if vs_name == "no_uplink":
            continue
        bond_mode = vs.get("bond_mode", "")
        for cluster in vs.get("clusters", []):
            cluster_ext_id = cluster.get("ext_id", "")
            cluster_name = next((name for name, ext in cluster_ext_map.items() if ext == cluster_ext_id), cluster_ext_id)
            hosts_map = cluster_hosts.get(cluster_ext_id, {})
            host_details = host_details_map.get(cluster_ext_id, {})
            switch_name, switch_ip = switch_details_map.get(cluster_ext_id, ("", ""))
            for host in cluster.get("hosts", []):
                host_ext_id = host.get("ext_id", "")
                details = host_details.get(host_ext_id, {})
                host_name = details.get("name", hosts_map.get(host_ext_id, "Unknown"))
                host_ip = details.get("ip", "")
                host_serial = details.get("serial", "")
                host_nics = host.get("host_nics", [])
                if not host_nics:
                    rows.append({
                        "pc_name": pc_name,
                        "cluster_name": cluster_name,
                        "host_name": host_name,
                        "host_ip": host_ip,
                        "host_serial_no": host_serial,
                        "virtual_switch": vs_name,
                        "host_interfaces": "",
                        "bond_mode": bond_mode,
                        "switch_name": switch_name,
                        "switch_ip": switch_ip
                    })
                else:
                    for iface in host_nics:
                        rows.append({
                            "pc_name": pc_name,
                            "cluster_name": cluster_name,
                            "host_name": host_name,
                            "host_ip": host_ip,
                            "host_serial_no": host_serial,
                            "virtual_switch": vs_name,
                            "host_interfaces": iface,
                            "bond_mode": bond_mode,
                            "switch_name": switch_name,
                            "switch_ip": switch_ip
                        })
    return rows

def write_host_network_csv(data, columns, output_path):
    """
    Write list of dicts to CSV with given columns and output path.
    """
    import datetime
    import csv
    from pathlib import Path
    # If output_path is a directory, create a filename inside it with the required naming convention
    output_dir = Path(output_path)
    if output_dir.is_dir():
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d-%H-%M-%S')
        csv_file = output_dir / f"PC_{pc_name}_host_network_report_{timestamp}.csv"
    else:
        csv_file = output_dir
    with open(csv_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        for row in data:
            writer.writerow(row)
    print(f"Output file created: {csv_file}")

def write_filenames(output_files,filename):
    """
    Writes the filename to the CSV file 
    """
    try:
        with open(filename,'a') as file:
            for output_file in output_files:
                # print(output_file)
                file.write(output_file+"\n")
        #print("Filename details have been written to '{}'\n".format(filename)) 
    except Exception as e :
        print(f"!!! An unexpected error occured : {e}")
        exit(1)

def write_to_file(list_of_dict,filename,mode,purpose=""):
    """
    Writes the script output to the CSV file 
    """
    try:
        with open(filename, mode=mode, newline='') as file:
            writer = csv.DictWriter(file, fieldnames=list(list_of_dict[0].keys()))
            writer.writeheader()
            writer.writerows(list_of_dict)
        print("{} Report details have been written to '{}'\n".format(purpose,filename))  
    except Exception as e :
        print(f"!!! An unexpected error occured : {e}")
        exit(1)

def main():
    parser = argparse.ArgumentParser(description="Generate Nutanix VM network report.")
    parser.add_argument("--pc_ip", required=True, help="Prism Central IP Address")
    parser.add_argument("--pc_user", required=True, help="Prism Central Username")
    parser.add_argument("--pc_secret", required=True, help="Prism Central Password")
    parser.add_argument('--output_path', required=True, help='Path of output file')
    parser.add_argument('--output_files_name', required=False, help='File to copy the output filenames')
    parser.add_argument('--clusters', required=True, help="Enter Cluster Names separated by comma")
    args = parser.parse_args()

    cluster_names = [c.strip() for c in args.clusters.split(",") if c.strip()]
    if not cluster_names:
        print("[ERROR] No cluster selected!")
        exit(1)

    clusters_api = initialize_clustermgmt_api(args.pc_ip, args.pc_user, args.pc_secret)
    cluster_ext_map = get_cluster_ext_map(clusters_api,cluster_names)
    global pc_name
    pc_name = get_pc_name(clusters_api)

    output_path = args.output_path
    if output_path.endswith("/"):
        output_path = output_path[:-1]
    filename_host_network = Path(output_path + "/PC_" + pc_name +  "_host_network_" + current_time.strftime("%Y-%m-%d-%H-%M-%S") + ".csv")

    cluster_hosts = get_hosts_by_clusters(clusters_api, cluster_ext_map)

    # get virtual switches
    networking_apis = initialize_networking_api(args.pc_ip, args.pc_user, args.pc_secret)
    virtual_switches_api = networking_apis["virtual_switches"]
    virtual_switches = virtual_switches_api.list_virtual_switches(_limit=100).to_dict()

    # Fetch host details for each cluster
    host_details_map = {}
    switch_details_map = {}

    if (len(cluster_ext_map) == 0):
        print("No clusters selected in {}. Exiting !!! \n".format(pc_name))
        exit(0)

    for cluster_name, cluster_ext_id in cluster_ext_map.items():
        host_details_map[cluster_ext_id] = fetch_host_details(cluster_ext_id, args.pc_ip, args.pc_user, args.pc_secret)
        switch_details_map[cluster_ext_id] = fetch_switch_details(cluster_ext_id, args.pc_ip, args.pc_user, args.pc_secret)
    # write_virtual_switches_csv(virtual_switches, pc_name, cluster_ext_map, cluster_hosts, host_details_map, switch_details_map, args.output_path)
    data = get_virtual_switches_data(virtual_switches, pc_name, cluster_ext_map, cluster_hosts, host_details_map, switch_details_map)
    columns = ["pc_name", "cluster_name", "host_name", "host_ip", "host_serial_no", "virtual_switch", "host_interfaces", "bond_mode", "switch_name", "switch_ip"]
    # write_host_network_csv(data, columns, args.output_path)
    write_to_file(list_of_dict=data,filename=filename_host_network,mode='a',purpose="Host Network")

    output_files_name = ""
    if args.output_files_name:
        output_files_name = Path(output_path + "/" +args.output_files_name)  
        filenames = [str(filename_host_network)]
        write_filenames(filenames,filename=output_files_name) 

    print("------------Nutanix Host Network Report Generation Completed ------------\n\n")                  


if __name__ == "__main__":
    print("Preparing Nutanix Host Network Report ....")
    main()