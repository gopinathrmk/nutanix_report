import csv
import argparse
from datetime import datetime, timedelta, timezone
from getpass import getpass
from ntnx_vmm_py_client import Configuration as VmmConfiguration, ApiClient as VmmApiClient
from ntnx_vmm_py_client.api import StatsApi, VmApi
from ntnx_vmm_py_client import DownSamplingOperator
from ntnx_clustermgmt_py_client import Configuration as ClusterMgmtConfiguration, ApiClient as ClusterMgmtApiClient
from ntnx_clustermgmt_py_client.api import ClustersApi
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def initialize_clients(pc_ip, pc_username, pc_password):
    vmm_config = VmmConfiguration()
    vmm_config.host = pc_ip
    vmm_config.username = pc_username
    vmm_config.password = pc_password
    vmm_config.verify_ssl = False 
    vmm_client = VmmApiClient(configuration=vmm_config)

    clustermgmt_config = ClusterMgmtConfiguration()
    clustermgmt_config.host = pc_ip
    clustermgmt_config.username = pc_username
    clustermgmt_config.password = pc_password
    clustermgmt_config.verify_ssl = False 
    clustermgmt_client = ClusterMgmtApiClient(configuration=clustermgmt_config)
    return vmm_client, clustermgmt_client

def get_cluster_details(clustermgmt_client, cluster_name):
    cluster_api = ClustersApi(clustermgmt_client) # type: ignore
    clusters = cluster_api.list_clusters().data
    for cluster in clusters:
        if cluster.name == cluster_name:
            return cluster
    return None

def get_host_details(clustermgmt_client):
    cluster_api = ClustersApi(clustermgmt_client) # type: ignore
    hosts = cluster_api.list_hosts().data
    return hosts

def get_vm_details(vmm_client, host_id):
    vm_api = VmApi(vmm_client)
    vms = vm_api.list_vms(_filter=f"host/extId eq '{host_id}'").data
    return vms

def get_vm_memory_usage(vmm_client, vm_id):
    stats_api = StatsApi(vmm_client)

    end_time = datetime.now(timezone.utc) - timedelta(minutes=5)
    start_time = end_time - timedelta(minutes=5)

    sampling_interval = 60
    select = "stats/memoryUsagePpm,extId"
    stat_type = DownSamplingOperator.AVG

    vm_stats = stats_api.get_vm_stats_by_id(
            vm_id,
            _startTime=start_time,
            _endTime=end_time,
            _samplingInterval=sampling_interval,
            _statType=stat_type,
            _select=select,
        )
    
    vm_api = VmApi(vmm_client)
    vm = vm_api.get_vm_by_id(vm_id)
    if vm_stats.data.stats is None:
        print(f"No stats found for VM: {vm.data.name}.")
        return 0

    return vm_stats.data.stats[0].memory_usage_ppm

def convert_ppm_to_bytes(memory_usage_ppm, memory_capacity_bytes):
    memory_usage_ppm = float(memory_usage_ppm)
    memory_capacity_bytes = float(memory_capacity_bytes)
    return int((memory_usage_ppm / 1_000_000) * memory_capacity_bytes)

def main():
    parser = argparse.ArgumentParser(description="Get cluster's host memory usage details.")
    parser.add_argument('--pc_ip', required=True, help='PC IP address')
    parser.add_argument('--pc_username', required=True, help='PC Username')
    parser.add_argument('--cluster_name', required=True, help='Cluster Name')
    args = parser.parse_args()

    pc_password = getpass("Enter PC Password: ")

    vmm_client, clustermgmt_client = initialize_clients(args.pc_ip, args.pc_username, pc_password)
    cluster = get_cluster_details(clustermgmt_client, args.cluster_name)
    if not cluster:
        print(f"Cluster {args.cluster_name} not found.")
        return

    hosts = get_host_details(clustermgmt_client)
    cluster_memory_usage = []
    total_vms = 0
    print(f"Please wait while we fetch the VMs utilization details for {args.cluster_name} cluster...")

    for host in hosts:
        vms = get_vm_details(vmm_client, host.ext_id)
        total_memory_usage_bytes = 0
        print(f"Fetching details for host: {host.host_name}")
        for vm in vms:
            memory_usage_ppm = get_vm_memory_usage(vmm_client, vm.ext_id)
            if memory_usage_ppm is None:
                print(f"Memory usage for VM {vm.name} not found.")
                continue
            memory_usage_bytes = convert_ppm_to_bytes(memory_usage_ppm, vm.memory_size_bytes)
            total_memory_usage_bytes += memory_usage_bytes  
    
        print(f"Total Memory Usage for host {host.host_name}: {total_memory_usage_bytes} bytes")
        print(f"Total VMs for host {host.host_name}: {len(vms)}")
        total_vms += len(vms)

        cluster_memory_usage.append({
            "Cluster Name": args.cluster_name,
            "Host Name": host.host_name,
            "Memory Capacity": host.memory_size_bytes,
            "Memory Consumed in bytes": total_memory_usage_bytes,
            "Memory Consumed in percent" : total_memory_usage_bytes/host.memory_size_bytes * 100 
        })

    with open('cluster_memory_usage.csv', mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=["Cluster Name", "Host Name", "Memory Capacity", "Memory Consumed in bytes","Memory Consumed in percent"])
        writer.writeheader()
        writer.writerows(cluster_memory_usage)

    print("Memory usage details have been written to cluster_memory_usage.csv")

if __name__ == "__main__":
    main()
