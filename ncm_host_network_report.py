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

python ncm_report_host_network_amt.py  --pc_ip 10.136.136.8 --pc_user gopinath.sekar --pc_secret "Nutanix@123" --output_path /Users/amit.yadav/Downloads/projects/nutanix_report 
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
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d-%H-%M')
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
    # pc_name = get_pc_name(clusters_api)
    global pc_name

    cluster_hosts = get_hosts_by_clusters(clusters_api, cluster_ext_map)
    for cluster_ext_id, hosts in cluster_hosts.items():
        print(f"Cluster ExtId: {cluster_ext_id}")
        for host_ext_id, host_name in hosts.items():
            print(f"  Host ExtId: {host_ext_id}, Host Name: {host_name}")

            # host_nics = get_host_nic_by_host_id(clusters_api, cluster_ext_id, host_ext_id)
            # print(host_nics)
            # print("*"*100)
            # # exit()
            # print(f"  Host NICs for {host_name}: {host_nics}")

            # host_vnics = get_virtual_nic_by_host_id(clusters_api, cluster_ext_id, host_ext_id)
            # print(f" host_vnics: {json.dumps(host_vnics)}")
            # print("*"*100)
            # exit()

            # vnics = get_virtual_nic_by_id(clusters_api, cluster_ext_id, host_ext_id)
            # print(f"Virtual NICs for Host {host_name}: {json.dumps(vnics)}")
            # print("*" * 100)

    # get virtual switches
    networking_apis = initialize_networking_api(args.pc_ip, args.pc_user, args.pc_secret)
    virtual_switches_api = networking_apis["virtual_switches"]
    virtual_switches = virtual_switches_api.list_virtual_switches(_limit=100).to_dict()

    # Fetch host details for each cluster
    host_details_map = {}
    switch_details_map = {}
    for cluster_name, cluster_ext_id in cluster_ext_map.items():
        host_details_map[cluster_ext_id] = fetch_host_details(cluster_ext_id, args.pc_ip, args.pc_user, args.pc_secret)
        switch_details_map[cluster_ext_id] = fetch_switch_details(cluster_ext_id, args.pc_ip, args.pc_user, args.pc_secret)
    write_virtual_switches_csv(virtual_switches, pc_name, cluster_ext_map, cluster_hosts, host_details_map, switch_details_map, args.output_path)






if __name__ == "__main__":
    main()