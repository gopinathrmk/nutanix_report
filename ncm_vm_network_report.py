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

python ncm_report_vm_network.py  --pc_ip 10.136.136.8 --pc_user gopinath.sekar --pc_secret "Nutanix@123" --output_path /Users/amit.yadav/Downloads/projects/nutanix_report 
===============================================================================
"""

import datetime
import argparse
import csv
import datetime
import json
import urllib3
from pathlib import Path

from ntnx_vmm_py_client import ApiClient as VMMClient
from ntnx_vmm_py_client import Configuration as VMMConfiguration
from ntnx_vmm_py_client.api import VmApi
from ntnx_clustermgmt_py_client import ApiClient as ClusterMgmtClient
from ntnx_clustermgmt_py_client import Configuration as ClusterMgmtConfiguration
from ntnx_clustermgmt_py_client.api import ClustersApi
import ntnx_networking_py_client

pc_name = ""
current_time = datetime.datetime.now(datetime.timezone.utc)  # Use timezone-aware UTC datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def initialize_vmm_api(pc_ip, pc_user, pc_secret):
    config = VMMConfiguration()
    config.host = pc_ip
    config.username = pc_user
    config.password = pc_secret
    config.verify_ssl = False
    return VmApi(VMMClient(configuration=config))

def initialize_clustermgmt_api(api_server, username, password):
    config = ClusterMgmtConfiguration()
    config.host = api_server
    config.username = username
    config.password = password
    config.verify_ssl = False
    return ClustersApi(ClusterMgmtClient(configuration=config))

def initialize_subnets_api(api_server, username, password):
    config = ntnx_networking_py_client.Configuration()
    config.host = api_server
    config.username = username
    config.password = password
    config.verify_ssl = False
    return ntnx_networking_py_client.SubnetsApi(ntnx_networking_py_client.ApiClient(configuration=config))

def get_cluster_ext_map(clusters_api):
    clusters = clusters_api.list_clusters(_limit=100)
    return {entity.ext_id: entity.name for entity in clusters.data}

def get_subnet_ext_map(subnets_api):
    subnets = subnets_api.list_subnets(_limit=100)
    return {entity.ext_id: entity.name for entity in subnets.data}

def extract_vm_network_info(vm_json, pc_name, cluster_ext_map, subnet_ext_map):
    """Extract VM network info from a VM JSON object, outputting one row per NIC/IP, not as lists."""
    rows = []
    vm_name = vm_json.get("name", "")
    #OS = vm.guest_tools.guest_os_version if vm.guest_tools else "NA"
    OS = vm_json.get("guest_tools", {}).get("guest_os_version", "NA") if vm_json.get("guest_tools") else "NA"
    # if vm_name == "CTS-APP":
    # print(vm_json)
    # exit(0)
#    OS ="NA"
    cluster_ext_id = ""
    cluster_name = ""
    if isinstance(vm_json.get("cluster"), dict):
        cluster_ext_id = vm_json["cluster"].get("ext_id", "")
        cluster_name = cluster_ext_map.get(cluster_ext_id, "")
    nics = vm_json.get("nics", [])
    if not nics:
        rows.append({
            "VM_NAME": vm_name,
            "OS": OS,
            "MAC_ADDRESS": "",
            "IP_ADDRESS": "",
            "NIC_CONNECTED_STATUS": "",
            "SUBNET_NAME": "",
            "CLUSTER": cluster_name if cluster_name else cluster_ext_id,
            "PC": pc_name
        })
    else:
        for nic in nics:
            try:
                backing_info = nic.get("backing_info", {})
                mac_address = backing_info.get("mac_address", "")
                nic_connected = "True" if backing_info.get("is_connected", False) else "False"
                network_info = nic.get("network_info", {})
                subnet = network_info.get("subnet", {})
                subnet_extid = subnet.get("ext_id", "")
                subnet_name = subnet_ext_map.get(subnet_extid, subnet_extid)
                ipv4_info = network_info.get("ipv4_info", {})
                learned_ips = ipv4_info.get("learned_ip_addresses", []) if ipv4_info else []
                ip_written = False
                for ip_obj in learned_ips:
                    ip_val = ip_obj.get("value", "")
                    if ip_val:
                        rows.append({
                            "VM_NAME": vm_name,
                             "OS": OS,
                            "MAC_ADDRESS": mac_address,
                            "IP_ADDRESS": ip_val,
                            "NIC_CONNECTED_STATUS": nic_connected,
                            "SUBNET_NAME": subnet_name,
                            "CLUSTER": cluster_name if cluster_name else cluster_ext_id,
                            "PC": pc_name
                        })
                        ip_written = True
                ipv4_config = network_info.get("ipv4_config", {})
                ip_addr_obj = ipv4_config.get("ip_address", {}) if ipv4_config else {}
                ip_val = ip_addr_obj.get("value", "")
                if ip_val and not ip_written:
                    rows.append({
                        "VM_NAME": vm_name,
                         "OS": OS,
                        "MAC_ADDRESS": mac_address,
                        "IP_ADDRESS": ip_val,
                        "NIC_CONNECTED_STATUS": nic_connected,
                        "SUBNET_NAME": subnet_name,
                        "CLUSTER": cluster_name if cluster_name else cluster_ext_id,
                        "PC": pc_name
                    })
                elif not learned_ips and not ip_val:
                    rows.append({
                        "VM_NAME": vm_name,
                         "OS": OS,
                        "MAC_ADDRESS": mac_address,
                        "IP_ADDRESS": "",
                        "NIC_CONNECTED_STATUS": nic_connected,
                        "SUBNET_NAME": subnet_name,
                        "CLUSTER": cluster_name if cluster_name else cluster_ext_id,
                        "PC": pc_name
                    })
            except Exception as e:
                print(f"[ERROR] Failed to process NIC for VM '{vm_name}': {e}")
    return rows

def write_vm_network_csv(rows, output_path=None, output_files_name=None):
    if not rows:
        print("No VM network data found.")
        return
    now = datetime.datetime.now()
    timestamp = now.strftime("%Y-%m-%d-%H-%M-%S")
    filename = f"PC_PC_vm_network_inventory_{timestamp}.csv"
    output_file = Path(output_path or ".") / (output_files_name or filename)
    with open(output_file, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    print(f"VM network report written to {output_file}")

def get_pc_name(clusters_api):
    clusters = clusters_api.list_clusters()
    for cluster in clusters.data:
        if 'PRISM_CENTRAL' in getattr(cluster.config, 'cluster_function', []):
            return cluster.name
    return "PrismCentral"

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

    output_path = args.output_path
    clusters_api = initialize_clustermgmt_api(args.pc_ip, args.pc_user, args.pc_secret)
    # pc_name = get_pc_name(clusters_api)
    cluster_ext_map = get_cluster_ext_map(clusters_api)
    subnets_api = initialize_subnets_api(args.pc_ip, args.pc_user, args.pc_secret)
    subnet_ext_map = get_subnet_ext_map(subnets_api)
    vmm_api = initialize_vmm_api(args.pc_ip, args.pc_user, args.pc_secret)

    clusters = clusters_api.list_clusters()
    global pc_name
    i=0
    skip_index= []
    for cluster in clusters.data :
        # print(cluster.name, cluster.config.cluster_function)
        if 'PRISM_CENTRAL' in cluster.config.cluster_function:
            pc_name = cluster.name
            skip_index.append(i)
        elif (cluster.name not in cluster_names) and (cluster_names[0] != "ALL"):
            # print("Skipping Cluster: {} ".format(cluster.name))
            skip_index.append(i)
        i += 1

    if output_path.endswith("/"):
        output_path = output_path[:-1]

    filename_vm_network = Path(output_path + "/PC_" +  pc_name + "_vm_network_" + current_time.strftime("%Y-%m-%d-%H-%M-%S") + ".csv")

    if len(clusters.data) > len(skip_index):
        print("Fetching Details for Prism Central: {} ".format(pc_name))
    else:
        print("No clusters selected in {}. Exiting !!! \n".format(pc_name))
        exit(0)

    output_files_name = ""
    if args.output_files_name:
        output_files_name = Path(output_path + "/" +args.output_files_name)
        filenames = [str(filename_vm_network)]    
        write_filenames(filenames,filename=output_files_name)

    index=0  
    for cluster in  clusters.data :
        if index not in skip_index:
            print("\tFetching Details for Cluster: {} ".format(cluster.name))
            vms = vmm_api.list_vms(
            _filter=f"cluster/extId eq '{cluster.ext_id}'",
            _limit=100
            )
            total_vms_count = vms.metadata.total_available_results
            #print(f"Total VMs in cluster: {total_vms_count}")
            page_loop = (total_vms_count // 100) + 1
            #print(f"Page Loop: {page_loop}")
            
            for page in range(page_loop):
                # print("Page {}".format(page))
                vms = vmm_api.list_vms(
                    _filter=f"cluster/extId eq '{cluster.ext_id}'",
                    _limit=100,
                    _page=page
                    )
                if not vms.data:
                    break
                # for vm in vms.data:
                #     print(".",end='', flush=True)

                vms_data = vms.to_dict().get("data", []) if hasattr(vms, "to_dict") else vms.get("data", [])
                all_rows = []
                for vm in vms_data:
                    if not isinstance(vm, dict) or not vm.get("name"):
                        continue
                    all_rows.extend(extract_vm_network_info(vm, pc_name, cluster_ext_map, subnet_ext_map))
                # write_vm_network_csv(all_rows, args.output_path, args.output_files_name)
                write_to_file(
                    list_of_dict=all_rows,
                    filename=filename_vm_network,
                    mode='a',
                    purpose="\t\tVM Network Report : Page {}".format(page + 1)
                )
        index += 1
    print("------------Nutanix VM Network Report Generation Completed ------------\n\n")

if __name__ == "__main__":
    print("Preparing Nutanix VM Network Report ....")
    main()
