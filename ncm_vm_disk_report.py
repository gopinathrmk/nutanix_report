#!/usr/bin/env python3
"""
===============================================================================
 Script Name   : ncm_vm_host_inventory_report.py
 Description   : Generates VM and Host Inventory Reports
 Author        : Gopinath Sekar
 Created Date  : [2025-06-19]
 Last Modified : [YYYY-MM-DD]
 Version       : [v1.0.0]
 Usage         : python ncm_report.py  --pe_ip <IP> --pe_user admin --pe_secret <secret> --output_path "/home/rocky" --output_files_name <filename>
 Dependencies  : pip install requests urllib3 tabulate 
                pip install ntnx_vmm_py_client==4.0.1 ntnx_clustermgmt_py_client==4.0.1 ntnx_prism_py_client==4.0.1
===============================================================================
"""


from ntnx_vmm_py_client import ApiClient as VMMClient
from ntnx_vmm_py_client import Configuration as VMMConfiguration
from ntnx_vmm_py_client.rest import ApiException as VMMException
from ntnx_vmm_py_client.api import VmApi, StatsApi
from ntnx_vmm_py_client import DownSamplingOperator

from ntnx_clustermgmt_py_client import ApiClient as ClusterMgmtClient  # type: ignore
from ntnx_clustermgmt_py_client import Configuration as ClusterMgmtConfiguration  # type: ignore
from ntnx_clustermgmt_py_client.rest import ApiException as ClusterMgmtException  # type: ignore
from ntnx_clustermgmt_py_client.api import ClustersApi
from ntnx_clustermgmt_py_client.api import StorageContainersApi

from ntnx_prism_py_client import ApiClient as CategoryClient  # type: ignore
from ntnx_prism_py_client.api import CategoriesApi

import datetime
import argparse
# import getpass
import csv
# from tabulate import tabulate
from pathlib import Path
import pprint
import urllib3  # type: ignore

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

stat_type = DownSamplingOperator.AVG
sampling_interval = 3600*24  # in seconds

current_time = datetime.datetime.now(datetime.timezone.utc)  # Use timezone-aware UTC datetime
end_time = (current_time ).strftime("%Y-%m-%dT%H:%M:%SZ")  
start_time = (current_time - datetime.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ") 

# end_time = (current_time - datetime.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")  
# start_time = (current_time - datetime.timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ") 

GB_or_GiB = 1024  # 1024 for GiB, 1000 for GB
cluster_threshold = 0.7
pc_name = ""
filename_vm_disk = ""


def initialize_vmm_api(api_server, username, password):
    configuration = VMMConfiguration()
    configuration.host = api_server
    configuration.username = username
    configuration.password = password
    configuration.verify_ssl = False
    vmm_client = VMMClient(configuration=configuration)
    vm_api = VmApi(vmm_client)
    return vm_api


def initialize_vmm_stats_api(api_server, username, password):
    configuration = VMMConfiguration()
    configuration.host = api_server
    configuration.username = username
    configuration.password = password
    configuration.verify_ssl = False
    vmm_client = VMMClient(configuration=configuration)
    vm_stats_api = StatsApi(vmm_client)
    return vm_stats_api


def initialize_clustermgmt_api(api_server, username, password):
    configuration = ClusterMgmtConfiguration()
    configuration.host = api_server
    configuration.username = username
    configuration.password = password
    configuration.verify_ssl = False
    api_client = ClusterMgmtClient(configuration=configuration)
    clusters_api = ClustersApi(api_client)
    return clusters_api


def initialize_clustermgmt_storage_api(api_server, username, password):
    configuration = ClusterMgmtConfiguration()
    configuration.host = api_server
    configuration.username = username
    configuration.password = password
    configuration.verify_ssl = False
    api_client = ClusterMgmtClient(configuration=configuration)
    storage_container_api = StorageContainersApi(api_client)
    return storage_container_api


def initialize_category_api(api_server, username, password):
    configuration = ClusterMgmtConfiguration()
    configuration.host = api_server
    configuration.username = username
    configuration.password = password
    configuration.verify_ssl = False
    api_client = CategoryClient(configuration=configuration)
    category_api = CategoriesApi(api_client)

    return category_api


def get_avg_value(data):
    if data:
        return round(sum(item.value for item in data) / len(data))
    else:
        return 0


def get_avg_list(list):
    return round(sum(list)/len(list)) if list else 0

def get_vm_stats(vm_api,vm_stats_api,cluster,category_api):

    total_vms_vcpu_allocated = 0
    total_vms_mem_allocated_bytes = 0
    total_vms_disk_allocated_bytes = 0
    total_vms_mem_allocated_gb =  0
    total_vms_disk_allocated_gb = 0

    total_vms_vcpu_consumed = 0
    total_vms_memory_consumed_bytes  = 0
    total_vms_disk_consumed_bytes = 0
    total_vms_memory_consumed_gb = 0
    total_vms_disk_consumed_gb = 0
    total_vms_hyper_vcpu_consumed = 0
    total_vms_hyper_memory_consumed_bytes  = 0
    total_vms_hyper_memory_consumed_gb = 0

    # Get all VMs in the cluster
    vms = vm_api.list_vms(
        _filter=f"cluster/extId eq '{cluster.ext_id}'",
        _limit=100
    )
    total_vms_count = vms.metadata.total_available_results
    #print(f"Total VMs in cluster: {total_vms_count}")
    page_loop = (total_vms_count // 100) + 1
    #print(f"Page Loop: {page_loop}")
    
    for page in range(page_loop):
        vm_stats_details_list = []  
        print("Page {}".format(page))
        vms = vm_api.list_vms(
            _filter=f"cluster/extId eq '{cluster.ext_id}'",
            _limit=100,
            _page=page
        )
        if not vms.data:
            break
        for vm in vms.data:
            print(".",end='', flush=True)

# Start of VM INFO            
            vm_ext_id = vm.ext_id
            #host info
            host_ext_id = vm.host.ext_id if vm.host else None

            #CPU and Memory allocated 
            vm_vcpu_allocated = vm.num_sockets * vm.num_cores_per_socket * vm.num_threads_per_core 
            vm_mem_allocated_bytes = vm.memory_size_bytes
            vm_mem_allocated_gb = round(vm_mem_allocated_bytes/ (GB_or_GiB ** 3))

            #VM IP Info
            vm_num_nic = len(vm.nics) if vm.nics else 0
            vm_ip_address_list = []
            nic_connection_status = []

            if vm_num_nic:
                for nic in vm.nics:
                    if nic.network_info and nic.network_info.ipv4_info:
                        for ip_address in nic.network_info.ipv4_info.learned_ip_addresses:
                            vm_ip_address_list.append(ip_address.value +"/"+ str(ip_address.prefix_length))
                    if nic.backing_info and nic.backing_info.is_connected:
                        nic_connection_status.append({nic.backing_info.mac_address:nic.backing_info.is_connected })


            #Disk Capacity
            vm_disk_capacity_bytes = 0
            if not vm.disks:
                vm_disk_capacity_bytes = 0
            else:
                for disk in vm.disks:
                    #print(type(disk.backing_info))
                    if hasattr(disk.backing_info, "disk_size_bytes"):
                        vm_disk_capacity_bytes += disk.backing_info.disk_size_bytes

            vm_disk_capacity_gb = round(vm_disk_capacity_bytes/ (GB_or_GiB ** 3))

            #NGT Info
            OS = vm.guest_tools.guest_os_version if vm.guest_tools else "NA"
            is_installed = vm.guest_tools.is_installed if vm.guest_tools else "No"
            ngt_version = vm.guest_tools.version if vm.guest_tools else "NA"

            #Categories
            category_list = []
            if vm.categories:
                for category in vm.categories:
                    category_resp = category_api.get_category_by_id(category.ext_id)
                    category_name = "{}:{}".format(category_resp.data.key , category_resp.data.value)
                    category_list.append(category_name)

            disk_details = []
            if vm.disks:
                for disk in vm.disks:
                    if disk.backing_info and hasattr(disk.backing_info, "disk_size_bytes"):
                        disk_address = disk.disk_address.to_dict()
                        disk_details.append(
                            {disk_address.get("bus_type"," ") +"-"+ str(disk_address.get("index"," ")) : str(round(disk.backing_info.disk_size_bytes /(GB_or_GiB ** 3))) + " GiB" })

                        global pc_name
                        vm_stats_details = {
                            "Name" :  vm.name,
                            "OS": OS,
                            "Power State" : vm.power_state,
                            "Disk Address" : disk_address.get("bus_type"," ") +"."+ str(disk_address.get("index"," ")),
                            "Disk Capacity (GiB)" : round(disk.backing_info.disk_size_bytes /(GB_or_GiB ** 3)),
                            "Parent Cluster" : cluster.name,
                            "PC " : pc_name,
                        }
                        vm_stats_details_list.append(vm_stats_details)
            else:
                vm_stats_details = {
                    "Name" :  vm.name,
                    "OS": OS,
                    "Power State" : vm.power_state,
                    "Disk Address" : "No Disk Info",
                    "Disk Capacity (GiB)" : 0,
                    "Parent Cluster" : cluster.name,
                    "PC " : pc_name,
                }
                vm_stats_details_list.append(vm_stats_details)

        print(".")
        header = True if page == 0 else False 
        #writing the VM stats page by page for memory efficiency
        write_to_file(list_of_dict=vm_stats_details_list,filename=filename_vm_disk,mode='a',header=header,purpose="VM Disk Report Page '{}'".format(page))


    all_vm_stats_details = {
        "total_vms_vcpu_allocated" : total_vms_vcpu_allocated,
        "total_vms_mem_allocated_bytes" : total_vms_mem_allocated_bytes,
        "total_vms_disk_allocated_bytes" : total_vms_disk_allocated_bytes,
        "total_vms_memory_gb_allocated" : total_vms_mem_allocated_gb,
        "total_vms_storage_gb_allocated" : total_vms_disk_allocated_gb,
        "total_vms_vcpu_consumed" : total_vms_vcpu_consumed,
        "total_vms_memory_consumed_bytes" : total_vms_memory_consumed_bytes,
        "total_vms_disk_consumed_bytes" : total_vms_disk_consumed_bytes,
        "total_vms_memory_consumed_gb" : total_vms_memory_consumed_gb,
        "total_vms_disk_consumed_gb" : total_vms_disk_consumed_gb,
        "total_vms_hyper_vcpu_consumed" : total_vms_hyper_vcpu_consumed,
        "total_vms_hyper_memory_consumed_bytes" : total_vms_hyper_memory_consumed_bytes
    }

    return all_vm_stats_details



#VM report is generated in get_vm_stats. 

#Preparing Host report 
    host_inventory_list = []
    for host_info in host_stats_details_list:
        host_inventory = {
            "Name" :host_info.get("name") ,
            "Cluster Name" : host_info.get("cluster_name") ,
            # "Block Serial No." : host_info.get("block_serial"), # node serial number not available. 
            "Hypervisor Version": host_info.get("hypervisor_full_name"),
            "IP" : host_info.get("ip"),
            "Model" : host_info.get("model") ,
            "CPU Model" : host_info.get("cpu_model") ,
            "Physical CPU's" : host_info.get("num_of_sockets") ,
            "Cores Per Sockets " : host_info.get("cores_per_sockets") ,
            "Total CPU Cores " : host_info.get("num_cores"),
            "CPU Usage %" : round(host_info.get("cpu_usage_percent")) ,
            "Total Memory (GB)" : round(host_info.get("memory_capacity_gb")) ,
            "Memory Usage %" : round(host_info.get("overall_memory_usage_gb")/host_info.get("memory_capacity_gb") * 100) ,
            # "HA Reserved Memory (GB)" : round(host_info.get("ha_reserved_memory_gb")),
            "Total Capacity (GB)" :round(host_info.get("storage_capacity_gb")) ,
            "Free Space (GB)" : round(host_info.get("free_physical_storage_gb")) ,
            #"Hypervisor Version " : "", #couldn't get 
            "Nic Count " : host_info.get("nic_count") ,
            "Active VMs" :  host_info.get("no_active_vm") ,
            #"Total VMs" : host.hypervisor.number_of_vms, # all VMs are active VM
            "PC " : host_info.get("pc_name") , #for datacenter
            #"Configuration " : "" # No configuration info 
        }
        host_inventory_list.append(host_inventory)

    # pprint.pprint(remaining_vm_list)
    return host_inventory_list


def write_to_file(list_of_dict,filename,mode,header=True,purpose=""):
    """
    Writes the script output to the CSV file 
    """
    try:
        with open(filename, mode=mode, newline='') as file:
            writer = csv.DictWriter(file, fieldnames=list(list_of_dict[0].keys()))
            writer.writeheader() if header else None
            writer.writerows(list_of_dict)
        print("{} Report details have been written to '{}'".format(purpose,filename))  
    except Exception as e :
        print(f"!!! An unexpected error occured : {e}")
        exit(1)

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


def main():
    # Parse command line arguments
    # Example usage: python script.py --pc_ip <ip> --username <username> --cluster_name <cluster_name>
    parser = argparse.ArgumentParser(description="Calculate VM allocation per TShirt size.")
    parser.add_argument("--pc_ip", required=True, help="Prism Central IP Address")
    parser.add_argument("--pc_user", required=True, help="Prism Central Username")
    parser.add_argument("--pc_secret", required=True, help="Prism Central Password") 
    parser.add_argument('--output_path', required=True, help='Path of output file')
    parser.add_argument('--output_files_name', required=False, help='File to copy the output filenames')
    parser.add_argument('--clusters', required=True, help="Enter Cluster Names separated by comma")


#    parser.add_argument("--cluster_name", required=True, help="Cluster Name")
    args = parser.parse_args()
#    password = getpass.getpass(prompt="Enter password: ")
    cluster_names = [c.strip() for c in args.clusters.split(",") if c.strip()]
    if not cluster_names:
        print("[ERROR] No cluster selected!")
        exit(1)

    output_path = args.output_path
    # Initialize VMM API
    vmm_api = initialize_vmm_api(args.pc_ip, args.pc_user, args.pc_secret)
    # Initialize VMM Stats API
    vmm_stats_api = initialize_vmm_stats_api(args.pc_ip, args.pc_user, args.pc_secret)
    # Initialize Cluster Management API
    clusters_api = initialize_clustermgmt_api(args.pc_ip, args.pc_user, args.pc_secret)
    # Initialize Cluster Management Storage API
    storage_container_api = initialize_clustermgmt_storage_api(args.pc_ip, args.pc_user, args.pc_secret)

    category_api = initialize_category_api(args.pc_ip, args.pc_user, args.pc_secret)

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

    global filename_vm_disk
    filename_vm_disk = Path(output_path + "/PC_" +  pc_name + "_vm_disk_" + current_time.strftime("%Y-%m-%d-%H-%M-%S") + ".csv")


    if len(clusters.data) > len(skip_index):
        print("Fetching Details for Prism Central: {} ".format(pc_name))
    else:
        print("No clusters selected in {}. Exiting !!! \n".format(pc_name))
        exit(0)

    output_files_name = ""
    if args.output_files_name:
        output_files_name = Path(output_path + "/" +args.output_files_name)
        filenames = [str(filename_vm_disk)]    
        write_filenames(filenames,filename=output_files_name)

    index=0 
    for cluster in clusters.data :
        #if 'AOS' in cluster.config.cluster_function and cluster.name in cluster_names:
        if index not in skip_index:
            print("\tFetching Details for Cluster: {} ".format(cluster.name))
            all_vm_stats_details = get_vm_stats(vmm_api,vmm_stats_api,cluster,category_api)
            print("")
        index += 1
    print("------------Nutanix VM Disk Report Generation Completed ------------\n\n")                   

if __name__ == "__main__":
    print("Preparing Nutanix VM Disk Report ....")
    main()