#!/usr/bin/env python3
"""
===============================================================================
 Script Name   : ncm_remaining_vm.py
 Description   : Calculate Remaining VM based on cluster resources available 
 Author        : Gopinath Sekar
 Created Date  : [2025-06-19]
 Last Modified : [YYYY-MM-DD]
 Version       : [v1.0.0]
 Usage         : ncm_remaining_vm.py  --pe_ip <IP> --pe_user admin --pe_secret <secret> --output_path "/home/rocky" --output_files_name <filename>
 Dependencies  : pip install python-csv argparse requests datetime urllib3 tabulate pathlib paramiko
                 pip install ntnx_vmm_py_client ntnx_clustermgmt_py_client ntnx_prism_py_client
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
import json
import os
import argparse
import getpass
import csv
from tabulate import tabulate
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

GB_or_GiB = 1024
cluster_threshold = 0.7
pc_name = ""

config_file_path = os.path.join(os.path.dirname(__file__), "cts_ncm_aiops_config.json")
with open(config_file_path, "r") as config_file:
    config_data = json.load(config_file)
    tshirt_sizes = config_data["VM_TShirt_Sizes"]
    environment = config_data["Environment"]


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


def get_cluster_stats(clusters_api,cluster):

    cluster_stats_details = {}

    #Fetching the number of cores in the cluster
    hosts = clusters_api.list_hosts_by_cluster_id(cluster.ext_id)
    cluster_hosts = [h for h in hosts.data if h.cluster.name == cluster.name]
    #print(f"Cluster hosts: {cluster_hosts}")
    cpu_details = []
    num_vcpu = 0
    cpu_capacity_hz = 0
    for host in cluster_hosts:
        host_id = host.ext_id
        host_info = clusters_api.get_host_by_id(cluster.ext_id, host_id)
        #print(f"Host ID: {host_id}")
        #print(f"Host Info: {host_info}")
        num_vcpu += host_info.data.number_of_cpu_threads
        #cpu_capacity_hz += host_info.data.cpu_capacity_hz
        cpu_details.append({
            "host_id": host_id,
            "numCpuThreads": host_info.data.number_of_cpu_threads,
            #"cpuCapacityHz": host_info.data.cpu_capacity_hz
        })
    #cpu_capacity_ghz = round(cpu_capacity_hz / 1_000_000_000, 2)
    #print(f"Total CPU Capacity: {cpu_capacity_ghz} GHz")

    #Fetching Cluster Stats
    cluster_stats = clusters_api.get_cluster_stats(
        cluster.ext_id,
        _startTime=start_time,
        _endTime=end_time,
        _samplingInterval=sampling_interval,
        _statType=stat_type,
        _select = "*"
        # _select="cpuCapacityHz,cpuUsageHz,hypervisorCpuUsagePpm,memoryCapacityBytes," \
        # "aggregateHypervisorMemoryUsagePpm,overallMemoryUsageBytes,storageCapacityBytes," \
        # "storageUsageBytes,logicalStorageUsageBytes,freePhysicalStorageBytes"  # Request specific properties
    )
    #print(f"Cluster stats: {cluster_stats}")
    #input("Press Enter to continue...")

    # cpuCapacityHz = cluster_stats.data.cpu_capacity_hz[0].value if cluster_stats.data.cpu_capacity_hz else 0
    # cpuUsageHz = get_avg_value(cluster_stats.data.cpu_usage_hz)
    hypervisor_cpu_usage_ppm = get_avg_value(cluster_stats.data.hypervisor_cpu_usage_ppm)
    num_vcpu_used = round((hypervisor_cpu_usage_ppm * num_vcpu)/1000000)
    num_vcpu_available = num_vcpu - num_vcpu_used

    memory_capacity_bytes = cluster_stats.data.memory_capacity_bytes[0].value if cluster_stats.data.memory_capacity_bytes else 0
    aggregate_hypervisor_memory_usage_ppm = get_avg_value(cluster_stats.data.aggregate_hypervisor_memory_usage_ppm)
    overall_memory_usage_bytes = get_avg_value(cluster_stats.data.overall_memory_usage_bytes)

    hypervisor_memory_usage_bytes =  round((aggregate_hypervisor_memory_usage_ppm/1000_000 * memory_capacity_bytes),2)
    memory_available_bytes = memory_capacity_bytes - overall_memory_usage_bytes

    memory_capacity_gb = round(memory_capacity_bytes / (GB_or_GiB ** 3))
    overall_memory_usage_gb = round(overall_memory_usage_bytes / (GB_or_GiB ** 3))
    hypervisor_memory_usage_gb = round(hypervisor_memory_usage_bytes / (GB_or_GiB ** 3))
    ha_reserved_memory_gb = round((overall_memory_usage_gb - hypervisor_memory_usage_gb),2)
    memory_available_gb  = round(memory_available_bytes / (GB_or_GiB ** 3))

    storage_capacity_bytes = cluster_stats.data.storage_capacity_bytes[0].value
    logical_storage_usage_bytes = get_avg_value(cluster_stats.data.logical_storage_usage_bytes)
    storage_usage_bytes = get_avg_value(cluster_stats.data.storage_usage_bytes)
    free_physical_storage_bytes = get_avg_value(cluster_stats.data.free_physical_storage_bytes )
    # storage_available_bytes = logical_storage_usage_bytes - storage_usage_bytes

    storage_capacity_gb = round(storage_capacity_bytes / (GB_or_GiB ** 3))
    logical_storage_usage_gb = round(logical_storage_usage_bytes / (GB_or_GiB ** 3))
    storage_usage_gb = round(storage_usage_bytes / (GB_or_GiB ** 3))
    free_physical_storage_gb = round(free_physical_storage_bytes / (GB_or_GiB ** 3))


    cluster_stats_details = {
        "vcpu_capacity" : num_vcpu,
        "vcpu_used" : num_vcpu_used,
        "vcpu_available" : num_vcpu_available,
        "memory_capacity_gb" : memory_capacity_gb,
        "overall_memory_usage_gb" : overall_memory_usage_gb,
        "hypervisor_memory_usage_gb": hypervisor_memory_usage_gb,
        "ha_reserved_memory_gb" : ha_reserved_memory_gb,
        "memory_available_gb" : memory_available_gb,
        "storage_capacity_gb" : storage_capacity_gb,
        "logical_storage_usage_gb" : logical_storage_usage_gb,
        "storage_usage_gb" : storage_usage_gb,
        "free_physical_storage_gb" : free_physical_storage_gb,
        # "storage_gb_free" : storage_free_gb,
        "memory_capacity_bytes" : memory_capacity_bytes,
        "overall_memory_usage_bytes" : overall_memory_usage_bytes,
        "memory_available_bytes" : memory_available_bytes,
        "storage_capacity_bytes": storage_capacity_bytes,
        "logical_storage_usage_bytes" : logical_storage_usage_bytes,
        "storage_used_bytes":  storage_usage_bytes,
        "free_physical_storage_bytes" : free_physical_storage_bytes
    }

    return cluster_stats_details


def get_host_stats(clusters_api,cluster):

    total_num_vcpu = 0 
    total_memory_capacity_gb = 0
    total_disk_size_gb = 0 
    total_storage_capacity_gb = 0
    total_ha_reserved_memory_gb = 0


    hosts = clusters_api.list_hosts_by_cluster_id(cluster.ext_id)

    host_stats_details_list = []
    for host in hosts.data:
        #print("Host name: {} , Host Id {}, ".format(host.host_name, host.ext_id))

#Start of host info 
        num_vcpu = host.number_of_cpu_threads 
        memory_capacity_bytes = host.memory_size_bytes 
        disk_size_bytes = 0
        for disk in host.disk:
            disk_size_bytes += disk.size_in_bytes 

        memory_capacity_gb =  round(memory_capacity_bytes / (GB_or_GiB ** 3),2)
        disk_size_gb = round(disk_size_bytes / (GB_or_GiB ** 3),2)

#End of host info 

#Start of host stats
        host_stats = clusters_api.get_host_stats(                                                 
                cluster.ext_id,
                extId = host.ext_id,
                _startTime=start_time,
                _endTime=end_time,
                _samplingInterval=sampling_interval,
                _statType=stat_type,
                _select="*",
                #_select="cpuCapacityHz"
            )

        # print(host_stats)
        # print(host_stats.data.cpu_capacity_hz)
        # cpu_capacity_hz = get_avg_value(host_stats.data.cpu_capacity_hz)
        # cpu_usage_hz = get_avg_value(host_stats.cpu_usage_hz)
        hypervisor_cpu_usage_ppm = get_avg_value(host_stats.data.hypervisor_cpu_usage_ppm)
        num_vcpu_used = round((hypervisor_cpu_usage_ppm * num_vcpu)/1000000)
        num_vcpu_available = num_vcpu - num_vcpu_used

        aggregate_hypervisor_memory_usage_ppm = get_avg_value(host_stats.data.aggregate_hypervisor_memory_usage_ppm)
        overall_memory_usage_bytes = get_avg_value(host_stats.data.overall_memory_usage_bytes)

        hypervisor_memory_usage_bytes =  round((aggregate_hypervisor_memory_usage_ppm/1000_000 * memory_capacity_bytes),2)
        memory_available_bytes = memory_capacity_bytes - overall_memory_usage_bytes

        overall_memory_usage_gb =  round(overall_memory_usage_bytes / (GB_or_GiB ** 3),2)
        hypervisor_memory_usage_gb =  round(hypervisor_memory_usage_bytes / (GB_or_GiB ** 3),2)
        ha_reserved_memory_gb = overall_memory_usage_gb - hypervisor_memory_usage_gb
        memory_available_gb  = round(memory_available_bytes / (GB_or_GiB ** 3))

        storage_capacity_bytes = get_avg_value(host_stats.data.storage_capacity_bytes)
        logical_storage_usage_bytes = get_avg_value(host_stats.data.logical_storage_usage_bytes)
        storage_usage_bytes = get_avg_value(host_stats.data.storage_usage_bytes)
        free_physical_storage_bytes = get_avg_value(host_stats.data.free_physical_storage_bytes)

        storage_capacity_gb =  round(storage_capacity_bytes / (GB_or_GiB ** 3),2)
        logical_storage_usage_gb =  round(logical_storage_usage_bytes / (GB_or_GiB ** 3),2)
        storage_usage_gb =  round(storage_usage_bytes / (GB_or_GiB ** 3),2)
        free_physical_storage_gb =  round(free_physical_storage_bytes / (GB_or_GiB ** 3),2)


        nics_physical = clusters_api.list_host_nics_by_host_id(cluster.ext_id,host.ext_id)


        host_info = {
            "name" : host.host_name ,
            "ext_id" : host.ext_id,
            "cluster_name" :  cluster.name,
            "ip" : host.ipmi.ip.ipv4.value + "/"+ str(host.ipmi.ip.ipv4.prefix_length),
            "model" : host.block_model, #no Server band 
            "cpu_model" : host.cpu_model,
            "num_of_sockets" : host.number_of_cpu_sockets,
            "num_vcpu" : num_vcpu,
            "cpu_usage_percent" : round(hypervisor_cpu_usage_ppm/10000,2),
            "num_vcpu_available" : num_vcpu_available,
            "memory_capacity_gb" : memory_capacity_gb ,
            "overall_memory_usage_gb" : overall_memory_usage_gb,
            "hypervisor_memory_usage_gb" : hypervisor_memory_usage_gb,
            "ha_reserved_memory_gb" : ha_reserved_memory_gb,
            # "disk_size_gb" : disk_size_gb,
            "storage_capacity_gb" : storage_capacity_gb,
            "logical_storage_usage_gb" : logical_storage_usage_gb,
            "storage_usage_gb" : storage_usage_gb,
            "free_physical_storage_gb" : free_physical_storage_gb,
            "nic_count" : len(nics_physical.data),
            "no_active_vm" :  host.hypervisor.number_of_vms,
            "pc_name" : pc_name #for datacenter
        }

        total_num_vcpu += num_vcpu
        total_memory_capacity_gb += memory_capacity_gb
        total_disk_size_gb += disk_size_gb
        total_storage_capacity_gb += storage_capacity_gb
        total_ha_reserved_memory_gb += ha_reserved_memory_gb

        host_stats_details_list.append(host_info)
    
    all_host_stats_details = {
        "total_num_vcpu" : total_num_vcpu,
        "total_memory_capacity_gb" : total_memory_capacity_gb,
        "total_disk_size_gb" : total_disk_size_gb,
        "total_storage_capacity_gb" : total_storage_capacity_gb,
        "total_ha_reserved_memory_gb" : total_ha_reserved_memory_gb
    }

    return host_stats_details_list,all_host_stats_details


def get_vm_stats(vm_api,vm_stats_api,cluster,category_api):

    vm_stats_details_list = []    
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
    total_no_vms = 0 

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
        # print(".")
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

            if vm_num_nic:
                for nic in vm.nics:
                    if nic.network_info and nic.network_info.ipv4_info:
                        for ip_address in nic.network_info.ipv4_info.learned_ip_addresses:
                            vm_ip_address_list.append(ip_address.value + str(ip_address.prefix_length))


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

            #Categories
            category_list = []
            if vm.categories:
                for category in vm.categories:
                    category_resp = category_api.get_category_by_id(category.ext_id)
                    category_name = "{}:{}".format(category_resp.data.key , category_resp.data.value)
                    category_list.append(category_name)

# End of VM Info 

#Start of VM stats

            vm_stats = vm_stats_api.get_vm_stats_by_id(
                    vm_ext_id,
                    _startTime=start_time,
                    _endTime=end_time,
                    _samplingInterval=sampling_interval,
                    _statType=stat_type,
                    _select="*"
                    #_select="stats/hypervisorMemoryUsagePpm,stats/diskUsagePpm,stats/numVcpusUsedPpm,stats/diskCapacityBytes"
                    #_select="stats/hypervisorMemoryUsagePpm,stats/diskUsagePpm,stats/numVcpusUsedPpm,stats/memoryUsagePpm,stats/hypervisorCpuUsagePpm,stats/diskCapacityBytes",
                    #_filter="stats/hypervisorMemoryUsagePpm,stats/diskUsagePpm,stats/numVcpusUsedPpm,stats/memoryUsagePpm,stats/hypervisorCpuUsagePpm,stats/diskCapacityBytes"
                    
            )
            # Parse hypervisor_memory_usage_ppm values from the stats list
            stats_list = vm_stats.data.stats if hasattr(vm_stats.data, "stats") else []

            vcpu_usage_ppm_value_list = []
            hyper_vcpu_usage_ppm_value_list =[]
            hyper_mem_usage_ppm_value_list = []
            mem_usage_ppm_value_list = []
            disk_usage_ppm_value_list = []
            vm_disk_capacity_bytes = 0 

            vcpu_usage_ppm_value = 0
            mem_usage_ppm_value = 0
            disk_usage_ppm_value = 0
            hyper_vcpu_usage_ppm_value = 0
            hyper_mem_usage_ppm_value = 0

            if not stats_list:
                vcpu_usage_ppm_value = 0
                hyper_mem_usage_ppm_value = 0
                disk_usage_ppm_value = 0 
            else:
                for stat in stats_list:
                    # print("Name: ",vm.name)
                    # print(stat)
                    # input("waiting on")
                    if hasattr(stat, "num_vcpus_used_ppm") and stat.num_vcpus_used_ppm != None:
                        vcpu_usage_ppm_value_list.append(stat.num_vcpus_used_ppm)
                    if hasattr(stat, "memory_usage_ppm") and stat.memory_usage_ppm!= None :
                        mem_usage_ppm_value_list.append(stat.memory_usage_ppm )
                    if hasattr(stat, "hypervisor_cpu_usage_ppm") and stat.hypervisor_cpu_usage_ppm != None :
                        hyper_vcpu_usage_ppm_value_list.append(stat.hypervisor_cpu_usage_ppm )          
                    if hasattr(stat, "hypervisor_memory_usage_ppm") and stat.hypervisor_memory_usage_ppm != None:
                        hyper_mem_usage_ppm_value_list.append(stat.hypervisor_memory_usage_ppm)
                    if hasattr(stat, "disk_usage_ppm") and stat.disk_usage_ppm != None :
                        disk_usage_ppm_value_list.append(stat.disk_usage_ppm)
                    
                    # if stat.disk_capacity_bytes:
                    #     vm_disk_capacity_bytes = stat.disk_capacity_bytes

                vcpu_usage_ppm_value = get_avg_list(vcpu_usage_ppm_value_list)
                mem_usage_ppm_value = get_avg_list(mem_usage_ppm_value_list)
                disk_usage_ppm_value = get_avg_list(disk_usage_ppm_value_list)
                hyper_vcpu_usage_ppm_value = get_avg_list(hyper_vcpu_usage_ppm_value_list)
                hyper_mem_usage_ppm_value = get_avg_list(hyper_mem_usage_ppm_value_list)


            vm_vcpu_consumed = round((vcpu_usage_ppm_value * vm_vcpu_allocated ) / 1000000)
            vm_mem_consumed_bytes = round ((mem_usage_ppm_value * vm_mem_allocated_bytes) / 1000000)
            vm_disk_consumed_bytes = round((disk_usage_ppm_value * vm_disk_capacity_bytes) / 1000000)
            vm_hyper_vcpu_consumed = round((hyper_vcpu_usage_ppm_value * vm_vcpu_allocated ) / 1000000)
            vm_hyper_mem_consumed_bytes = round ((hyper_mem_usage_ppm_value * vm_mem_allocated_bytes) / 1000000)

            vm_mem_consumed_gb = round( vm_mem_consumed_bytes / (GB_or_GiB ** 3),2)
            vm_hyper_mem_consumed_gb = round( vm_hyper_mem_consumed_bytes / (GB_or_GiB ** 3),2)
            vm_disk_consumed_gb  = round ( vm_disk_consumed_bytes / (GB_or_GiB ** 3),2)

            #troubleshoot for each VM 
            # print(vm.name,vm_vcpu_allocated,vm_mem_allocated_gb,vm_disk_capacity_gb,",",
            #       vm_vcpu_consumed,vm_hyper_mem_consumed_gb,vm_disk_consumed_gb,",",
            #       vcpu_usage_ppm_value/10000,hyper_mem_usage_ppm_value/10000,disk_usage_ppm_value/10000,",",
            #       hyper_vcpu_usage_ppm_value/10000,mem_usage_ppm_value/10000,"d")
            # print(".", end="")

            total_vms_vcpu_allocated += vm_vcpu_allocated
            total_vms_mem_allocated_bytes += vm_mem_allocated_bytes
            total_vms_disk_allocated_bytes += vm_disk_capacity_bytes
            total_vms_mem_allocated_gb +=  vm_mem_allocated_gb
            total_vms_disk_allocated_gb += vm_disk_capacity_gb

            total_vms_vcpu_consumed += vm_vcpu_consumed
            total_vms_memory_consumed_bytes  += vm_mem_consumed_bytes
            total_vms_disk_consumed_bytes += vm_disk_consumed_bytes
            total_vms_memory_consumed_gb += vm_mem_consumed_gb
            total_vms_disk_consumed_gb += vm_disk_consumed_gb
            total_vms_hyper_vcpu_consumed += vm_hyper_vcpu_consumed
            total_vms_hyper_memory_consumed_bytes  += vm_hyper_mem_consumed_bytes
            total_vms_hyper_memory_consumed_gb += vm_hyper_mem_consumed_gb
            total_no_vms += 1

            global pc_name
            # vm_stats_details = {
            #     "Name" :  vm.name,
            #     "Power State" : vm.power_state,
            #     "vCPU" : vm_vcpu_allocated,
            #     "Memory (GB)" : vm_mem_allocated_gb,
            #     "Disk Space(GB)" : vm_disk_capacity_gb,
            #     "vNIC" : vm_num_nic,
            #     "IP Address" : vm_ip_address_list,
            #     "OS" : OS,
            #     "NGT Installed" : is_installed ,
            #     "Categories" : category_list,
            #     "Parent Cluster" : cluster.name,
            #     "PC " : pc_name,
            #     "host_ext_id" : host_ext_id,
            #     "memory_usage" : vm_mem_consumed_gb
            # }

            vm_stats_details = {
                "name" :  vm.name,
                "cluster_name" : cluster.name,
                "power_state" : vm.power_state,
                "ip" : vm_ip_address_list,
                "num_vcpu_allocated" : vm_vcpu_allocated,
                "num_vcpu_consumed" : vm_vcpu_consumed,
                "num_vcpu_available" : vm_vcpu_allocated - vm_vcpu_consumed,
                "memory_allocated_gb" : vm_mem_allocated_gb,
                "memory_usage_gb" : vm_mem_consumed_gb,
                "hypervisor_memory_usage" : vm_hyper_mem_consumed_gb,
                "storage_allocated_gb" : vm_disk_capacity_gb,
                "storage_usage_gb" : vm_disk_consumed_gb, #todo not working
                "PC " : pc_name,
                "host_ext_id" : host_ext_id,
            }

            # vm_stats_details_list.append(vm_stats_details) Use only for troubleshooting

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
        "total_vms_hyper_memory_consumed_bytes" : total_vms_hyper_memory_consumed_bytes,
        "total_no_vms" : total_no_vms
    }

    return all_vm_stats_details


def get_optimal_num_vms(cluster_stats_details,all_vm_stats_details,oc_ratio,type="demand"):
    vms_allocation = {}
    available_resources = {}

    if type == "demand":
        available_resources = {
            "vCPU": cluster_stats_details.get("vcpu_available") * oc_ratio.get("vcpu_ratio") * cluster_threshold,
            "memory_bytes": cluster_stats_details.get("memory_available_bytes") * oc_ratio.get("memory_ratio") * cluster_threshold,
            "disk_bytes": cluster_stats_details.get("free_physical_storage_bytes") * oc_ratio.get("storage_ratio") * cluster_threshold
        }
    elif type == "allocation":
        resource_capacity = {
            "vCPU": cluster_stats_details.get("vcpu_capacity") * oc_ratio.get("vcpu_ratio") * cluster_threshold,
            "memory_gb": cluster_stats_details.get("memory_capacity_gb") * oc_ratio.get("memory_ratio") * cluster_threshold,
            "disk_gb": cluster_stats_details.get("logical_storage_usage_gb") * oc_ratio.get("storage_ratio") * cluster_threshold
        }    

        resource_allocated = {
            "vCPU": all_vm_stats_details.get("total_vms_vcpu_allocated") ,
            "memory_gb": all_vm_stats_details.get("total_vms_memory_gb_allocated") ,
            "disk_gb": all_vm_stats_details.get("total_vms_storage_gb_allocated") 
        }    

        available_resources = {
            "vCPU" : resource_capacity["vCPU"] - resource_allocated["vCPU"],
            "memory_bytes" : (resource_capacity["memory_gb"] - resource_allocated["memory_gb"]) * (GB_or_GiB ** 3),
            "disk_bytes" : (resource_capacity["disk_gb"] - resource_allocated["disk_gb"]) * (GB_or_GiB ** 3)
        }


    # Ensure no negative resources
    available_resources = {k: max(0, v) for k, v in available_resources.items()}
    
    # For each TShirt size, calculate the number of VMs that can be accommodated
    for size, config in tshirt_sizes.items():
        
        # Calculate the number of VMs that can be accommodated for the current TShirt size
        vms_per_resource = {
            "vCPU": available_resources["vCPU"] // config["vCPU"],
            "Memory": available_resources["memory_bytes"] // (config["Memory"]*(GB_or_GiB ** 3)),
            "Disk": available_resources["disk_bytes"] //  (config["Disk"]*(GB_or_GiB ** 3))
        }
        
        # Get the optimal number of VMs for the current TShirt size
        vms_allocation[size] = int(min(vms_per_resource.values()))
    
    return vms_allocation


def get_report_interim(cluster_stats_details,all_host_stats_details,all_vm_stats_details): #tocomment
    # This is used for troubleshooting 
    filename ="/home/rocky/nutanix_report/output/interim-report"
    write_to_file(cluster_stats_details,filename=filename,mode='a',purpose="interim-report")
    write_to_file(all_host_stats_details,filename=filename,mode='a',purpose="interim-report")
    write_to_file(all_vm_stats_details,filename=filename,mode='a',purpose="interim-report")


def get_report(vmm_api,vmm_stats_api,storage_container_api,clusters_api,cluster,category_api):
    # This function calls and collect cluster level, vm level and host level information.
    #Then structure it in the output format as required.. 

    cluster_stats_details = get_cluster_stats(clusters_api,cluster)
    all_vm_stats_details = get_vm_stats(vmm_api,vmm_stats_api,cluster,category_api)

    # host_stats_details_list,all_host_stats_details = get_host_stats(clusters_api,cluster) #tocomment
    # get_report_interim([cluster_stats_details],host_stats_details_list,vm_stats_details_list) #troubleshooting

    remaining_vm_list = {"demand":{},"allocation":{} }

    for env_name,oc_ratio in environment.items():
        remaining_vm_list["demand"][env_name] = get_optimal_num_vms(cluster_stats_details,all_vm_stats_details,oc_ratio,type="demand")
        remaining_vm_list["allocation"][env_name] = get_optimal_num_vms(cluster_stats_details,all_vm_stats_details,oc_ratio,type="allocation")


#Preparing  resource Report
    report_resources =  []

    report_resources.append({
        "Cluster Name" : cluster.name ,
        "vcpu Capacity" : cluster_stats_details.get("vcpu_capacity"),
        "vcpu Allocated" : all_vm_stats_details.get("total_vms_vcpu_allocated"),
        "vcpu Consumed" : cluster_stats_details.get("vcpu_used"),
        "vcpu Free" : cluster_stats_details.get("vcpu_available"),
        "Memory Capacity (GiB)" : cluster_stats_details.get("memory_capacity_gb"),
        "Memory Allocated (GiB)" : all_vm_stats_details.get("total_vms_memory_gb_allocated"),
        "Memory Overall Consumed (GiB)" : cluster_stats_details.get("overall_memory_usage_gb"),
        "Memory Hypervisor Consumed (GiB)" : cluster_stats_details.get("hypervisor_memory_usage_gb"),
        "Memory HA Reservation Consumed (GiB)" : cluster_stats_details.get("ha_reserved_memory_gb"),
#        "Memory Consumed - Actual (GB)" : all_vm_stats_details.get("total_vms_memory_consumed_gb"),
        "Memory Free (GiB)" :cluster_stats_details.get("memory_available_gb"),
        "Storage Physcial Capacity (GiB)" : cluster_stats_details.get("storage_capacity_gb"),
        "Storage Logical Capacity (GiB)" : cluster_stats_details.get("logical_storage_usage_gb"),
        "Storage Allocated (GiB) " : all_vm_stats_details.get("total_vms_storage_gb_allocated"),
        "Storage Consumed (GiB)" :  cluster_stats_details.get("storage_usage_gb"),
        "Storage Free (GiB)" :  cluster_stats_details.get("free_physical_storage_gb")
    })

#Preparing Remaining VM Report :
    report_remaining_vm =  []
    env_names  = list(environment.keys())

    for i  in range(3):
        env = env_names[i]
        report_remaining_vm.append({
            "Cluster Name" : cluster.name ,
            "Environment" : env ,
            "Small [Demand]" : remaining_vm_list.get("demand").get(env).get("Small"),
            "Medium [Demand]" : remaining_vm_list.get("demand").get(env).get("Medium"),
            "Large [Demand]" :  remaining_vm_list.get("demand").get(env).get("Large"),
            "Small [Allocation]" : remaining_vm_list.get("allocation").get(env).get("Small"),
            "Medium [Allocation]" : remaining_vm_list.get("allocation").get(env).get("Medium"),
            "Large [Allocation]" : remaining_vm_list.get("allocation").get(env).get("Large")
        })


    # pprint.pprint(remaining_vm_list)
    return report_resources ,report_remaining_vm


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
    parser = argparse.ArgumentParser(description="Calculate Remaining VM based on cluster resources available.")
    parser.add_argument("--pc_ip", required=True, help="Prism Central IP Address")
    parser.add_argument("--pc_user", required=True, help="Prism Central Username")
    parser.add_argument("--pc_secret", required=True, help="Prism Central Password") 
    parser.add_argument('--output_path', required=True, help='Path of output file')
    parser.add_argument('--output_files_name', required=False, help='File to copy the output filenames')

    args = parser.parse_args()

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
    for cluster in clusters.data :
        if 'PRISM_CENTRAL' in cluster.config.cluster_function:
            pc_name = cluster.name
            break
    
    if output_path.endswith("/"):
        output_path = output_path[:-1]
    filename_resources = Path(output_path + "/PC_" + pc_name +  "_resources_" + current_time.strftime("%Y-%m-%d-%H-%M") + ".csv")
    filename_remaining_vm = Path(output_path + "/PC_" + pc_name +  "_remaining_vm_" + current_time.strftime("%Y-%m-%d-%H-%M") + ".csv")

    output_files_name = ""
    if args.output_files_name:
        output_files_name = Path(output_path + "/" +args.output_files_name)  
        filenames = [str(filename_resources),str(filename_remaining_vm)]
        write_filenames(filenames,filename=output_files_name) 

    print("Fetching Details for Prism Central: {} ".format(pc_name))
    for cluster in clusters.data :
        if 'AOS' in cluster.config.cluster_function:
            print("\tFetching Details for Cluster: {} ".format(cluster.name))
            report_resources ,report_remaining_vm = get_report(vmm_api,vmm_stats_api,storage_container_api,clusters_api,cluster,category_api)
            print("")

            #Writing both the reports to files
            write_to_file(list_of_dict=report_resources,filename=filename_resources,mode='a',purpose="Cluster Resources")
            write_to_file(list_of_dict=report_remaining_vm,filename=filename_remaining_vm,mode='a',purpose="Remaining VM")
            

if __name__ == "__main__":
    main()
