#!/usr/bin/env python3
"""
===============================================================================
 Script Name   : ncm_report.py
 Description   : Generates VM and Host Inventory Reports
 Author        : Amit Yadav
 Created Date  : [2025-06-19]
 Last Modified : [YYYY-MM-DD]
 Version       : [v1.0.0]
 Usage         : python ncm_report_cluster_amt.py  --pe_ip <IP> --pe_user admin --pe_secret <secret> --output_path "/home/rocky" --output_files_name <filename>
 Dependencies  : pip install python-csv argparse requests datetime urllib3 tabulate pathlib 
                pip install ntnx_vmm_py_client ntnx_clustermgmt_py_client ntnx_prism_py_client

python ncm_report_cluster_amt.py  --pc_ip 10.136.136.5 --pc_user gopinath.sekar --pc_secret "Nutanix@123" --output_path /Users/amit.yadav/Downloads/projects/nutanix_report --clusters Trigonometry,Vector,Trigonometry
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

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


from ntnx_clustermgmt_py_client import ApiClient as ClusterMgmtClient  # type: ignore
from ntnx_clustermgmt_py_client import Configuration as ClusterMgmtConfiguration  # type: ignore
from ntnx_clustermgmt_py_client.rest import ApiException as ClusterMgmtException  # type: ignore
from ntnx_clustermgmt_py_client.api import ClustersApi



current_time = datetime.datetime.now(datetime.timezone.utc)  # Use timezone-aware UTC datetime
end_time = (current_time ).strftime("%Y-%m-%dT%H:%M:%SZ")  
start_time = (current_time - datetime.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ") 

# Variables to Fetch
EXT_ID = ""  # Add this variable for clarity
HOST_COUNT = ""
AOS_VERSION = ""
DARE_STATUS = ""
HA_STATUS = ""
RF =""
NAME_SERVER = ""
NTP_SERVER = ""

def initialize_clustermgmt_api(api_server, username, password):
    """Initialize and return the ClustersApi client."""
    configuration = ClusterMgmtConfiguration()
    configuration.host = api_server
    configuration.username = username
    configuration.password = password
    configuration.verify_ssl = False
    api_client = ClusterMgmtClient(configuration=configuration)
    return ClustersApi(api_client)


def get_cluster_ext_map(clusters_api):
    """Return a mapping of cluster names to extIds from the clusters API."""
    clusters = clusters_api.list_clusters()
    return {entity.name: entity.ext_id for entity in clusters.data}


def print_cluster_data(pc_ip, pc_user, pc_secret, cluster_extId):
    """Fetch and pretty-print cluster data for a given extId."""
    clusters_api = initialize_clustermgmt_api(pc_ip, pc_user, pc_secret)
    cluster = clusters_api.get_cluster_by_id(cluster_extId)
    cluster_dict = cluster.to_dict()
    print(json.dumps(cluster_dict, indent=4))

def ha_status(pc_ip, pc_user, pc_secret, cluster_extId):
    """Fetch and return HA state for a given cluster."""
    uri = f"https://{pc_ip}:9440/api/nutanix/v0.8/ha?proxyClusterUuid={cluster_extId}"
    headers = {
         "Content-Type": "application/json",
    }
    response = requests.get(uri, headers=headers, auth=(pc_user, pc_secret), verify=False)
    if response.status_code == 200:
        ha_info = response.json()
        return ha_info.get("haState", "")
    else:
        print(f"[ERROR] Failed to fetch HA status: {response.status_code} {response.text}")
        return ""


def extract_cluster_info(cluster_dict, args):
    # Safely extract required fields, skip if not present
    # data = cluster_dict.get("data", {})
    config = cluster_dict.get("config", {})
    network = cluster_dict.get("network", {})
    nodes = cluster_dict.get("nodes", {})

    # Helper to safely extract IP or FQDN
    def get_ntp_value(ntp):
        if ntp is None:
            return ""
        ipv4 = ntp.get("ipv4")
        if ipv4 and isinstance(ipv4, dict):
            return ipv4.get("value", "")
        fqdn = ntp.get("fqdn")
        if fqdn and isinstance(fqdn, dict):
            return fqdn.get("value", "")
        return ""

    def get_name_server_value(ns):
        if ns is None:
            return ""
        ipv4 = ns.get("ipv4")
        if ipv4 and isinstance(ipv4, dict):
            return ipv4.get("value", "")
        return ""

    return {
        "CLUSTER_NAME": cluster_dict.get("name", ""),
        "HOST_COUNT": nodes.get("number_of_nodes", ""),
        "AOS_VERSION": config.get("build_info", {}).get("version", ""),
        "DARE_STATUS": config.get("encryption_option") or "Not Enabled",
        # "HA_STATUS": config.get("operation_mode", ""),
         "HA_STATUS": ha_status(args.pc_ip, args.pc_user, args.pc_secret, cluster_dict.get("ext_id", "")),
        "RF": config.get("redundancy_factor", ""),
        "NAME_SERVER": ", ".join([
            get_name_server_value(ns) for ns in network.get("name_server_ip_list", []) if ns
        ]),
        "NTP_SERVER": ", ".join([
            get_ntp_value(ntp) for ntp in network.get("ntp_server_ip_list", []) if ntp
        ]),
    }

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
    parser = argparse.ArgumentParser(description="Generate Nutanix cluster report.")
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
    # cluster_ext_map = get_cluster_ext_map(clusters_api)
    # cluster_rows = []

    clusters = clusters_api.list_clusters()

    global pc_name
    i=0
    skip_index= []
    for cluster in clusters.data :
        # print(cluster.name, cluster.config.cluster_function)
        if 'PRISM_CENTRAL' in cluster.config.cluster_function:
            pc_name = cluster.name
        if (cluster.name not in cluster_names) and (cluster_names[0] != "ALL"):
            print("Skipping Cluster: {} ".format(cluster.name))
            skip_index.append(i)
        i += 1

    output_path = args.output_path
    if output_path.endswith("/"):
        output_path = output_path[:-1]
    filename_cluster_health = Path(output_path + "/PC_" + pc_name +  "_cluster_health_" + current_time.strftime("%Y-%m-%d-%H-%M") + ".csv")

    output_files_name = ""
    if args.output_files_name:
        output_files_name = Path(output_path + "/" +args.output_files_name)  
        filenames = [str(filename_cluster_health)]
        write_filenames(filenames,filename=output_files_name) 

    if len(clusters.data) > len(skip_index):
        print("Fetching Details for Prism Central: {} ".format(pc_name))
    else:
        print("No clusters selected in {}. Exiting !!!".format(pc_name))
        exit(0)
    
    index=0  
    cluster_rows = []
    for cluster in  clusters.data :
        if index not in skip_index:
            try:
                # cluster_obj = clusters_api.get_cluster_by_id(extId)
                print("\tFetching Details for Cluster: {} ".format(cluster.name))
                cluster_dict = cluster.to_dict()
                # print("cluster _dict: ", cluster_dict)
                row = extract_cluster_info(cluster_dict, args=args)
                cluster_rows.append(row)
                write_to_file(list_of_dict=cluster_rows,filename=filename_cluster_health,mode='a',purpose="Cluster({}) Resources ".format(cluster.name))
            except ClusterMgmtException as e:
                print(f"[ERROR] Failed to process cluster '{cluster}': {e}")
        index += 1


if __name__ == "__main__":
    main()