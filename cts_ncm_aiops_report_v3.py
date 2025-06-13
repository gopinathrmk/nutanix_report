import datetime
import json
import os

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

import argparse
import getpass
import csv

import urllib3  # type: ignore

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

stat_type = DownSamplingOperator.AVG
sampling_interval = 3600*24  # in seconds

current_time = datetime.datetime.now(datetime.timezone.utc)  # Use timezone-aware UTC datetime
end_time = (current_time - datetime.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")  
start_time = (current_time - datetime.timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ") 

GB_or_GiB = 1000
cluster_threshold = 0.7

config_file_path = os.path.join(os.path.dirname(__file__), "cts_ncm_aiops_config.json")
with open(config_file_path, "r") as config_file:
    config_data = json.load(config_file)
    tshirt_sizes = config_data["VM_TShirt_Sizes"]
    environment = config_data["Environment"]


def main():
    # Parse command line arguments
    # Example usage: python script.py --pc_ip <ip> --username <username> --cluster_name <cluster_name>
    parser = argparse.ArgumentParser(description="Calculate VM allocation per TShirt size.")
    parser.add_argument("--pc_ip", required=True, help="Prism Central IP Address")
    parser.add_argument("--username", required=True, help="Username")
    parser.add_argument("--cluster_name", required=True, help="Cluster Name")
    args = parser.parse_args()
    if not args.pc_ip or not args.username or not args.cluster_name:
        parser.error("All of --pc_ip, --username, and --cluster_name must be provided.")

    password = getpass.getpass(prompt="Enter password: ")

    # Initialize VMM API
    vmm_api = initialize_vmm_api(args.pc_ip, args.username, password)
    # Initialize VMM Stats API
    vmm_stats_api = initialize_vmm_stats_api(args.pc_ip, args.username, password)
    # Initialize Cluster Management API
    clusters_api = initialize_clustermgmt_api(args.pc_ip, args.username, password)
    # Initialize Cluster Management Storage API
    storage_container_api = initialize_clustermgmt_storage_api(args.pc_ip, args.username, password)
    # Get cluster CPU details
    cluster_config_num_cpu_threads = get_cluster_cpu_details(clusters_api, args.cluster_name)
    print("------------------------------------------------------------")    
    print(f"Cluster CPU details: {cluster_config_num_cpu_threads} CPU Threads")
    # Get cluster memory and storage capacity details
    cluster_memory_capacity, cluster_storage_capacity = get_cluster_memory_disk_details(clusters_api, args.cluster_name)
    print(f"Cluster Memory details: {cluster_memory_capacity} GB")
    print(f"Cluster Storage details: {cluster_storage_capacity} GB")
    print("------------------------------------------------------------")    

    # Get cluster allocation details
    total_vms_vcpu_allocated = get_cluster_cpu_allocation_details(clusters_api, vmm_api, args.cluster_name)
    print(f"Cluster CPU allocation details: {total_vms_vcpu_allocated} vCPUs allocated")
    total_vms_memory_allocated = get_cluster_memory_allocation_details(clusters_api, args.cluster_name)
    print(f"Cluster Memory allocation details: {total_vms_memory_allocated} GB allocated")
    total_vms_disk_allocated = get_cluster_disk_allocation_details(clusters_api, storage_container_api, args.cluster_name)
    print(f"Cluster Storage allocation details: {total_vms_disk_allocated} GB allocated")
    print("------------------------------------------------------------")    

    # Get cluster consumption details
    total_vms_vcpu_consumed = get_cluster_cpu_consumption_details(clusters_api, cluster_config_num_cpu_threads, args.cluster_name)
    print(f"Cluster CPU consumption details: {total_vms_vcpu_consumed} vCPUs consumed")
    total_vms_memory_consumed = get_cluster_memory_consumption_details(clusters_api, vmm_api, vmm_stats_api, args.cluster_name)
    print(f"Cluster Memory consumption details: {total_vms_memory_consumed} GB consumed")
    total_vms_disk_consumed = get_cluster_disk_consumption_details(clusters_api, args.cluster_name)
    print(f"Cluster Storage consumption details: {total_vms_disk_consumed} GB consumed")

    print("------------------------------------------------------------")    
    #cpu_overscription_ratio = round((total_vms_vcpu_allocated / cluster_config_num_cpu_threads), 2)
    #print(f"Cluster CPU oversubscription ratio: {cpu_overscription_ratio}")

    # Get number of Powered On and Powered Off VMs
    num_powered_on_vms, num_powered_off_vms, num_hosts = get_cluster_details(clusters_api, vmm_api, args.cluster_name)


    cluster_logical_config = {
        "vCPU": cluster_config_num_cpu_threads,
        "Memory": cluster_memory_capacity,  # in GiB
        "Disk": cluster_storage_capacity    # in GiB
    }

    cluster_allocation_config = {
        "vCPU": total_vms_vcpu_allocated,
        "Memory": total_vms_memory_allocated,  # in GiB
        "Disk": total_vms_disk_allocated    # in GiB
    }

    cluster_consumption_config = {
        "vCPU": total_vms_vcpu_consumed,
        "Memory": total_vms_memory_consumed,  # in GiB
        "Disk": total_vms_disk_consumed    # in GiB
    }
    
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    csv_file = f"CTS_{args.cluster_name}_Cluster_VM_Capacity_Report_{timestamp}.csv"

    fieldnames = [
        "Name",
        "Environment",
        "Total Hosts",
        "Total VMs",
        "Powered ON VMs",
        "Powered OFF VMs",
        "VMs Remaining (Small Size, Allocation)",
        "VMs Remaining (Medium Size, Allocation)",
        "VMs Remaining (Large Size, Allocation)",
        "VMs Remaining (Small Size, Demand)",
        "VMs Remaining (Medium Size, Demand)",
        "VMs Remaining (Large Size, Demand)",
        "vCPUs Remaining % (Allocation)",
        "vCPU Remaining % (Demand)",
        "Memory Remaining % (Allocation)",
        "Memory Remaining % (Demand)",
        "Storage Remaining % (Allocation)",
        "Storage Remaining % (Demand)",
        "vCPUs Remaining (Allocation)",
        "vCPUs Remaining (Demand)",
        "Memory Remaining GB (Allocation)",
        "Memory Remaining GB (Demand)",
        "Storage Remaining GB (Allocation)",
        "Storage Remaining GB (Demand)",
        "Total Usable vCPUs",
        "Total Usable Memory GB",
        "Total Usable Storage GB",
        "Total Effective vCPUs",
        "Total Effective Memory GB",
        "Total Effective Storage GB",
        "vCPUs Allocated (Allocation)",
        "Memory Allocated GB (Allocation)",
        "Storage Allocated GB (Allocation)",
        "vCPUs Used (Demand)",
        "Memory Used GB (Demand)",
        "Storage Used GB (Demand)",
    ]

    rows = []

    for env_type in ["Production", "Development"]:
        env_config = environment.get(env_type, {})
        vcpu_ratio = env_config.get("vcpu_ratio", 1)
        memory_ratio = env_config.get("memory_ratio", 1)
        storage_ratio = env_config.get("storage_ratio", 1)

        # Precompute adjusted logical resources for this environment
        adjusted_logical = {
            "vCPU": cluster_logical_config["vCPU"] * vcpu_ratio * cluster_threshold,
            "Memory": cluster_logical_config["Memory"] * memory_ratio * cluster_threshold,
            "Disk": cluster_logical_config["Disk"] * storage_ratio * cluster_threshold,
        }

        # Allocation-based
        vms_allocation = get_optimal_num_vms(adjusted_logical, cluster_allocation_config)
        print("-----------------------------------------------------------------------------------------------------------------")
        print(f"Number of VMs that can be accommodated as per allocation in {env_type}: {vms_allocation}")

        # Consumption-based
        vms_consumption = get_optimal_num_vms(adjusted_logical, cluster_consumption_config)
        print("-----------------------------------------------------------------------------------------------------------------")
        print(f"Number of VMs that can be accommodated as per consumption in {env_type}: {vms_consumption}")

        def zero_if_negative(val):
            if isinstance(val, dict):
                return {k: zero_if_negative(v) for k, v in val.items()}
            try:
                return val if val >= 0 else 0
            except TypeError:
                return val

        # Helper to compute remaining (absolute and percent) for each resource and config
        def remaining(resource, config):
            rem = adjusted_logical[resource] - config[resource]
            percent = (rem / adjusted_logical[resource] * 100) if adjusted_logical[resource] else 0
            return zero_if_negative(round(rem)), zero_if_negative(round(percent))

        vcpu_rem_alloc, vcpu_rem_pct_alloc = remaining("vCPU", cluster_allocation_config)
        vcpu_rem_demand, vcpu_rem_pct_demand = remaining("vCPU", cluster_consumption_config)
        mem_rem_alloc, mem_rem_pct_alloc = remaining("Memory", cluster_allocation_config)
        mem_rem_demand, mem_rem_pct_demand = remaining("Memory", cluster_consumption_config)
        disk_rem_alloc, disk_rem_pct_alloc = remaining("Disk", cluster_allocation_config)
        disk_rem_demand, disk_rem_pct_demand = remaining("Disk", cluster_consumption_config)

        row = {
            "Name": args.cluster_name,
            "Environment": env_type,
            "Total Hosts": zero_if_negative(num_hosts),
            "Total VMs": zero_if_negative(num_powered_on_vms + num_powered_off_vms),
            "Powered ON VMs": zero_if_negative(num_powered_on_vms),
            "Powered OFF VMs": zero_if_negative(num_powered_off_vms),
            "VMs Remaining (Small Size, Allocation)": zero_if_negative(vms_allocation.get("Small", 0)),
            "VMs Remaining (Medium Size, Allocation)": zero_if_negative(vms_allocation.get("Medium", 0)),
            "VMs Remaining (Large Size, Allocation)": zero_if_negative(vms_allocation.get("Large", 0)),
            "VMs Remaining (Small Size, Demand)": zero_if_negative(vms_consumption.get("Small", 0)),
            "VMs Remaining (Medium Size, Demand)": zero_if_negative(vms_consumption.get("Medium", 0)),
            "VMs Remaining (Large Size, Demand)": zero_if_negative(vms_consumption.get("Large", 0)),
            "vCPUs Remaining % (Allocation)": vcpu_rem_pct_alloc,
            "vCPU Remaining % (Demand)": vcpu_rem_pct_demand,
            "Memory Remaining % (Allocation)": mem_rem_pct_alloc,
            "Memory Remaining % (Demand)": mem_rem_pct_demand,
            "Storage Remaining % (Allocation)": disk_rem_pct_alloc,
            "Storage Remaining % (Demand)": disk_rem_pct_demand,
            "vCPUs Remaining (Allocation)": vcpu_rem_alloc,
            "vCPUs Remaining (Demand)": vcpu_rem_demand,
            "Memory Remaining GB (Allocation)": mem_rem_alloc,
            "Memory Remaining GB (Demand)": mem_rem_demand,
            "Storage Remaining GB (Allocation)": disk_rem_alloc,
            "Storage Remaining GB (Demand)": disk_rem_demand,
            "Total Usable vCPUs": zero_if_negative(round(cluster_logical_config["vCPU"])),
            "Total Usable Memory GB": zero_if_negative(round(cluster_logical_config["Memory"])),
            "Total Usable Storage GB": zero_if_negative(round(cluster_logical_config["Disk"])),
            "Total Effective vCPUs": zero_if_negative(round(adjusted_logical["vCPU"])),
            "Total Effective Memory GB": zero_if_negative(round(adjusted_logical["Memory"])),
            "Total Effective Storage GB": zero_if_negative(round(adjusted_logical["Disk"])),
            "vCPUs Allocated (Allocation)": zero_if_negative(cluster_allocation_config["vCPU"]),
            "Memory Allocated GB (Allocation)": zero_if_negative(cluster_allocation_config["Memory"]),
            "Storage Allocated GB (Allocation)": zero_if_negative(cluster_allocation_config["Disk"]),
            "vCPUs Used (Demand)": zero_if_negative(cluster_consumption_config["vCPU"]),
            "Memory Used GB (Demand)": zero_if_negative(cluster_consumption_config["Memory"]),
            "Storage Used GB (Demand)": zero_if_negative(cluster_consumption_config["Disk"])
        }
        rows.append(row)

    print("-----------------------------------------------------------------------------------------------------------------")    
    with open(csv_file, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

    print(f"{args.cluster_name} cluster's VM capacity report written to {csv_file} successfully.")

def get_cluster_details(clusters_api, vm_api, cluster_name):
    clusters = clusters_api.list_clusters()
    cluster_ext_id = None

    cluster = next((c for c in clusters.data if c.name == cluster_name), None)
    if not cluster:
        raise ValueError(f"Cluster '{cluster_name}' not found.")

    cluster_ext_id = cluster.ext_id

    hosts = clusters_api.list_hosts_by_cluster_id(cluster_ext_id)
    num_hosts = len(hosts.data)
    print(f"Number of Hosts in Cluster: {num_hosts}")

    # Get all Powered ON VMs in the cluster
    vms = vm_api.list_vms(
        _filter=f"powerState eq Vmm.Ahv.Config.PowerState'ON' and cluster/extId eq '{cluster_ext_id}'"
    )
    num_powered_on_vms = vms.metadata.total_available_results
    print(f"Number of Powered ON VMs: {num_powered_on_vms}")

    # Get all Powered Off VMs in the cluster
    powered_off_vms = vm_api.list_vms(
        _filter=f"powerState eq Vmm.Ahv.Config.PowerState'OFF' and cluster/extId eq '{cluster_ext_id}'"
    )
    num_powered_off_vms = powered_off_vms.metadata.total_available_results
    print(f"Number of Powered OFF VMs: {num_powered_off_vms}")

    return num_powered_on_vms, num_powered_off_vms, num_hosts


def get_cluster_disk_consumption_details(clusters_api, cluster_name):
    # Get all clusters and find the one matching the given cluster_name
    clusters = clusters_api.list_clusters()
    cluster_ext_id = None

    cluster = next((c for c in clusters.data if c.name == cluster_name), None)
    if not cluster:
        raise ValueError(f"Cluster '{cluster_name}' not found.")

    cluster_ext_id = cluster.ext_id

    cluster_stats = clusters_api.get_cluster_stats(
        cluster_ext_id,
        _startTime=start_time,
        _endTime=end_time,
        _samplingInterval=sampling_interval,
        _statType=stat_type,
        _select="storageUsageBytes"  # Request specific properties
    )

    storage_consumed_gb = round(cluster_stats.data.storage_usage_bytes[0].value / (GB_or_GiB ** 3))

    # Replication factor is 2 for storage containers
    storage_consumed_gb = round(storage_consumed_gb/2)

    return storage_consumed_gb

def get_cluster_memory_consumption_details(clusters_api, vm_api, vm_stats_api, cluster_name):
    clusters = clusters_api.list_clusters()
    cluster_ext_id = None

    cluster = next((c for c in clusters.data if c.name == cluster_name), None)
    if not cluster:
        raise ValueError(f"Cluster '{cluster_name}' not found.")

    cluster_ext_id = cluster.ext_id

    # Get all VMs in the cluster
    vms = vm_api.list_vms(
        _filter=f"powerState eq Vmm.Ahv.Config.PowerState'ON' and cluster/extId eq '{cluster_ext_id}'",
        _limit=100
    )
    total_vms_count = vms.metadata.total_available_results
    #print(f"Total VMs in cluster: {total_vms_count}")
    page_loop = (total_vms_count // 100) + 1
    #print(f"Page Loop: {page_loop}")
    
    memory_allocation = {}
    total_vms_memory_consumed = 0

    for page in range(page_loop):
        vms = vm_api.list_vms(
            _filter=f"powerState eq Vmm.Ahv.Config.PowerState'ON' and cluster/extId eq '{cluster_ext_id}'",
            _limit=100,
            _page=page
        )
        if not vms.data:
            break
        for vm in vms.data:
            # Get memory stats for each VM using its ext_id
            #print(f"VM Details: {vm}")
            #input("Press Enter to continue...")
            vm_ext_id = vm.ext_id
    
            vm_stats = vm_stats_api.get_vm_stats_by_id(
                    vm_ext_id,
                    _startTime=start_time,
                    _endTime=end_time,
                    _samplingInterval=sampling_interval,
                    _statType=stat_type,
                    _select="stats/hypervisorMemoryUsagePpm"
            )
            # Parse hypervisor_memory_usage_ppm values from the stats list
            stats_list = vm_stats.data.stats if hasattr(vm_stats.data, "stats") else []
            mem_usage_ppm_value = None
            if not stats_list:
                mem_usage_ppm_value = 0
            else:
                for stat in stats_list:
                    if hasattr(stat, "hypervisor_memory_usage_ppm"):
                        mem_usage_ppm_value = stat.hypervisor_memory_usage_ppm
                        break
            #print(f"hypervisor_memory_usage_ppm values: {mem_usage_ppm_value}")
            if mem_usage_ppm_value is not None:
                # Calculate memory allocated based on usage percentage
                memory_usage_percentage = mem_usage_ppm_value
                # Convert percentage to GB
                memory_capacity_bytes = vm.memory_size_bytes
                # Calculate memory allocated based on usage percentage
                memory_consumed_bytes = (memory_usage_percentage / 1_000_000) * memory_capacity_bytes
                memory_allocated_gb = round(memory_consumed_bytes / (GB_or_GiB ** 3))
                total_vms_memory_consumed += memory_allocated_gb
                memory_allocation[vm.name] = {
                    "memoryCapacityBytes": memory_capacity_bytes,
                    "memoryConsumedGB": memory_allocated_gb
                }
            else:
                # Handle case where memory usage percentage is not available
                memory_allocation[vm.name] = {
                    "memoryCapacityBytes": memory_capacity_bytes,
                    "memoryConsumedGB": 0
                }
        #print(f"VM Memory allocation: {memory_allocation}")
        #print(f"Total VMs Memory consumed: {total_vms_memory_consumed} GB")

    return total_vms_memory_consumed


def get_cluster_cpu_consumption_details(clusters_api, cluster_config_num_cpu_threads, cluster_name):
    # Get all clusters and find the one matching the given cluster_name
    clusters = clusters_api.list_clusters()
    cluster_ext_id = None

    cluster = next((c for c in clusters.data if c.name == cluster_name), None)
    if not cluster:
        raise ValueError(f"Cluster '{cluster_name}' not found.")

    cluster_ext_id = cluster.ext_id
    
    cluster_stats = clusters_api.get_cluster_stats(
        cluster_ext_id,
        _startTime=start_time,
        _endTime=end_time,
        _samplingInterval=sampling_interval,
        _statType=stat_type,
        _select="hypervisorCpuUsagePpm"  # Request specific properties
    )
    #print(f"Cluster stats: {cluster_stats}")
    cpu_usage_percentage = cluster_stats.data.hypervisor_cpu_usage_ppm[0].value
    num_cpu_consumed = round((cpu_usage_percentage / 1_000_000) * cluster_config_num_cpu_threads)

    return num_cpu_consumed

def get_cluster_disk_allocation_details(clusters_api, storage_container_api, cluster_name):
    # Get all clusters and find the one matching the given cluster_name
    clusters = clusters_api.list_clusters()
    cluster_ext_id = None

    cluster = next((c for c in clusters.data if c.name == cluster_name), None)
    if not cluster:
        raise ValueError(f"Cluster '{cluster_name}' not found.")

    cluster_ext_id = cluster.ext_id
    
    # Get all storage containers in the cluster
    storage_containers = storage_container_api.list_storage_containers(
        filter=f"clusterExtId=={cluster_ext_id}"
    )
    #print(f"Storage containers: {storage_containers}")
    storage_allocated_gb = 0
    stat_type = DownSamplingOperator.LAST
    for container in storage_containers.data:
        container_ext_id = container.container_ext_id
        stats = storage_container_api.get_storage_container_stats(
            container_ext_id,
            _startTime=start_time,
            _endTime=end_time,
            _samplingInterval=sampling_interval,
            _statType=stat_type,
        )
        #print(f"Container stats: {stats}")
        #input("Press Enter to continue...")
        #Sum the pre-reduction bytes for the container
        if hasattr(stats.data, "data_reduction_overall_pre_reduction_bytes"):
            values = stats.data.data_reduction_overall_pre_reduction_bytes
            #print(f"Container pre-reduction bytes: {values}")
            if values and hasattr(values[0], "value"):
                storage_allocated_gb += round(values[0].value / (GB_or_GiB ** 3))

    storage_allocated_gb = round(storage_allocated_gb)
    # Replication factor is 2 for storage containers
    storage_allocated_gb = round(storage_allocated_gb/2)
    return storage_allocated_gb

def get_cluster_memory_allocation_details(clusters_api, cluster_name):
    # Get all clusters and find the one matching the given cluster_name
    clusters = clusters_api.list_clusters()
    cluster_ext_id = None

    cluster = next((c for c in clusters.data if c.name == cluster_name), None)
    if not cluster:
        raise ValueError(f"Cluster '{cluster_name}' not found.")

    cluster_ext_id = cluster.ext_id

    cluster_stats = clusters_api.get_cluster_stats(
        cluster_ext_id,
        _startTime=start_time,
        _endTime=end_time,
        _samplingInterval=sampling_interval,
        _statType=stat_type,
        _select="memoryCapacityBytes,aggregateHypervisorMemoryUsagePpm"  # Request specific properties
    )

    cluster_memory_usage_percentage = cluster_stats.data.aggregate_hypervisor_memory_usage_ppm[0].value
    # Convert percentage to GB
    memory_capacity_bytes = cluster_stats.data.memory_capacity_bytes[0].value
    # Calculate memory allocated based on usage percentage
    memory_allocated_bytes = (cluster_memory_usage_percentage / 1_000_000) * memory_capacity_bytes
    memory_allocated_gb = round(memory_allocated_bytes / (GB_or_GiB ** 3))
 
    return memory_allocated_gb


def get_cluster_cpu_details(clusters_api, cluster_name):
    # Get all clusters and find the one matching the given cluster_name
    clusters = clusters_api.list_clusters()
    cluster_ext_id = None

    cluster = next((c for c in clusters.data if c.name == cluster_name), None)
    if not cluster:
        raise ValueError(f"Cluster '{cluster_name}' not found.")

    cluster_ext_id = cluster.ext_id
    #print(f"Cluster external ID: {cluster_ext_id}")
    # Get all hosts in the cluster
    hosts = clusters_api.list_hosts_by_cluster_id(cluster_ext_id)
    cluster_hosts = [h for h in hosts.data if h.cluster.name == cluster_name]
    #print(f"Cluster hosts: {cluster_hosts}")
    cpu_details = []
    num_cpu_threads = 0
    cpu_capacity_hz = 0
    for host in cluster_hosts:
        host_id = host.ext_id
        host_info = clusters_api.get_host_by_id(cluster_ext_id, host_id)
        #print(f"Host ID: {host_id}")
        #print(f"Host Info: {host_info}")
        num_cpu_threads += host_info.data.number_of_cpu_threads
        #cpu_capacity_hz += host_info.data.cpu_capacity_hz
        cpu_details.append({
            "host_id": host_id,
            "numCpuThreads": host_info.data.number_of_cpu_threads,
            #"cpuCapacityHz": host_info.data.cpu_capacity_hz
        })
    #cpu_capacity_ghz = round(cpu_capacity_hz / 1_000_000_000, 2)
    #print(f"Total CPU Capacity: {cpu_capacity_ghz} GHz")
    return num_cpu_threads

def get_cluster_memory_disk_details(clusters_api, cluster_name):
    # Get all clusters and find the one matching the given cluster_name
    clusters = clusters_api.list_clusters()
    cluster_ext_id = None

    cluster = next((c for c in clusters.data if c.name == cluster_name), None)
    if not cluster:
        raise ValueError(f"Cluster '{cluster_name}' not found.")

    cluster_ext_id = cluster.ext_id
    #print(f"Cluster external ID: {cluster_ext_id}")
    
    cluster_stats = clusters_api.get_cluster_stats(
        cluster_ext_id,
        _startTime=start_time,
        _endTime=end_time,
        _samplingInterval=sampling_interval,
        _statType=stat_type,
        _select="memoryCapacityBytes,storageCapacityBytes"  # Request specific properties
    )
    #print(f"Cluster stats: {cluster_stats}")
    #input("Press Enter to continue...")
    memory_capacity_bytes = cluster_stats.data.memory_capacity_bytes[0].value
    storage_capacity_bytes = cluster_stats.data.storage_capacity_bytes[0].value

    # Convert bytes to GB
    memory_capacity_gb = round(memory_capacity_bytes / (GB_or_GiB ** 3))
    storage_capacity_gb = round(storage_capacity_bytes / (GB_or_GiB ** 3))

    # Replication factor is 2 for storage containers
    storage_capacity_gb = round(storage_capacity_gb/2)

    return memory_capacity_gb, storage_capacity_gb

def get_cluster_cpu_allocation_details(clusters_api, vm_api, cluster_name):
    clusters = clusters_api.list_clusters()
    cluster_ext_id = None

    cluster = next((c for c in clusters.data if c.name == cluster_name), None)
    if not cluster:
        raise ValueError(f"Cluster '{cluster_name}' not found.")

    cluster_ext_id = cluster.ext_id

    # Get all VMs in the cluster
    vms = vm_api.list_vms(
        _filter=f"powerState eq Vmm.Ahv.Config.PowerState'ON' and cluster/extId eq '{cluster_ext_id}'",
        _limit=100
    )
    total_vms_count = vms.metadata.total_available_results
    #print(f"Total VMs in cluster: {total_vms_count}")
    page_loop = (total_vms_count // 100) + 1
    #print(f"Page Loop: {page_loop}")

    cpu_allocation = {}
    total_vms_num_sockets = 0
    total_vms_num_cores_per_socket = 0
    total_vms_num_threads_per_core = 0
    total_vms_vcpu_allocated = 0

    for page in range(page_loop):
        vms = vm_api.list_vms(
            _filter=f"powerState eq Vmm.Ahv.Config.PowerState'ON' and cluster/extId eq '{cluster_ext_id}'",
            _limit=100,
            _page=page
        )
        if not vms.data:
            break
        for vm in vms.data:
            # Get the number of sockets, cores per socket, and threads per core for each VM
            total_vms_num_sockets = vm.num_sockets
            total_vms_num_cores_per_socket = vm.num_cores_per_socket
            total_vms_num_threads_per_core = vm.num_threads_per_core

            total_vms_vcpu_allocated += total_vms_num_sockets * total_vms_num_cores_per_socket * total_vms_num_threads_per_core
            
            cpu_allocation[vm.name] = {
                "num_sockets": vm.num_sockets,
                "num_cores_per_socket": vm.num_cores_per_socket,
                "threads_per_core": vm.num_threads_per_core
            }

    return total_vms_vcpu_allocated

def get_optimal_num_vms(adjusted_logical, cluster_compare_config):
    vms_allocation = {}

    adjusted_logical_vcpu = adjusted_logical["vCPU"]
    adjusted_logical_memory = adjusted_logical["Memory"]
    adjusted_logical_storage = adjusted_logical["Disk"]

    # For each TShirt size, calculate the number of VMs that can be accommodated
    for size, config in tshirt_sizes.items():
        # Calculate available resources for the given environment
        available_resources = {
            "vCPU": adjusted_logical_vcpu - cluster_compare_config["vCPU"],
            "Memory": adjusted_logical_memory - cluster_compare_config["Memory"],
            "Disk": adjusted_logical_storage - cluster_compare_config["Disk"]
        }
        # Ensure no negative resources
        available_resources = {k: max(0, v) for k, v in available_resources.items()}
        
        # Calculate the number of VMs that can be accommodated for the current TShirt size
        vms_per_resource = {
            "vCPU": available_resources["vCPU"] // config["vCPU"],
            "Memory": available_resources["Memory"] // config["Memory"],
            "Disk": available_resources["Disk"] // config["Disk"]
        }
        
        # Get the optimal number of VMs for the current TShirt size
        vms_allocation[size] = int(min(vms_per_resource.values()))
    
    return vms_allocation

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


if __name__ == "__main__":
    main()