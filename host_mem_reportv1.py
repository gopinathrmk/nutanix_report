import csv
import argparse
import requests
import json
from datetime import datetime, timedelta
import time 
import urllib3
from tabulate import tabulate
from pathlib import Path
import paramiko
#import pprint

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
}

api_server_port = "9440"
# Current time
now = datetime.now()
now_microseconds = int(now.timestamp() * 1_000_000)

# One hour before
one_hour_before = now - timedelta(minutes=60)
one_hour_before_microseconds = int(one_hour_before.timestamp() * 1_000_000)



# For token-based authentication, omit user and password (so that they default to None), and add the following header to
# the headers list: 'Authorization': 'Bearer <token value>'
def process_request(url, method, user=None, password=None, cert=None, files=None,headers=None, payload=None, params=None, secure=False, timeout=120, retries=5, exit_on_failure=True):
    """
    Processes a web request and handles result appropriately with retries.
    Returns the content of the web request if successful.
    """
    if payload is not None:
        payload = json.dumps(payload)

    sleep_between_retries=5
    
    while retries > 0:
        try:

            if method == 'GET':
                response = requests.get(
                    url,
                    headers=headers,
                    auth=(user, password) if user else None,
                    cert=cert if cert else None,
                    params=params,
                    verify=secure,
                    timeout=timeout
                )
            elif method == 'POST':
                response = requests.post(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password) if user else None,
                    params=params,
                    verify=secure,
                    timeout=timeout
                )
            elif method == 'PUT':
                response = requests.put(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password) if user else None,
                    files=files if files else None,
                    params=params,
                    verify=secure,
                    timeout=timeout
                )
            elif method == 'PATCH':
                response = requests.patch(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password) if user else None,
                    params=params,
                    verify=secure,
                    timeout=timeout
                )
            elif method == 'DELETE':
                response = requests.delete(
                    url,
                    headers=headers,
                    data=payload,
                    auth=(user, password) if user else None,
                    params=params,
                    verify=secure,
                    timeout=timeout
                )

        except requests.exceptions.RequestException as error_code:
            print('Error: {c}, Message: {m}'.format(c = type(error_code).__name__, m = str(error_code)))
            retries -= 1
            time.sleep(sleep_between_retries)
            print("In except")
            continue
        
        if response.ok:
            return response
        elif response.status_code == 409:
            print(response.text)
            retries -= 1
            if retries == 0:
                if exit_on_failure:
                    exit(response.status_code)
                else:
                    return response
            time.sleep(sleep_between_retries)
            continue
        else:
            print("Rest API Call to '{}' failed.".format(url))
            print(response)
            print(response.text)
            if exit_on_failure:
                exit(response.status_code)
            else:
                return response

def get_cluster_name(api_server,username,passwd):
    """
    Returns the cluster name from PE_IP 
    """

    api_server_endpoint = "/PrismGateway/services/rest/v1/cluster"
    url = "https://{}:{}{}".format(
        api_server,
        api_server_port,
        api_server_endpoint
    )
    method = "GET"
  
    resp = process_request(url,method,user=username,password=passwd,headers=headers,exit_on_failure=True)
    cluster_name  = resp.json().get("name")
   
    return cluster_name


def get_host_details(api_server,username,passwd):
    """
    Fetches the list of HOST in the clusters and its basic details 
    """
    api_server_endpoint = "/PrismGateway/services/rest/v1/hosts"
    url = "https://{}:{}{}".format(
        api_server,
        api_server_port,
        api_server_endpoint
    )
    method = "GET"
  
    resp = process_request(url,method,user=username,password=passwd,headers=headers,exit_on_failure=True)
    entities = resp.json().get("entities")
    #print(entities)

    hosts = []
    for entity in entities:
        host = {}
        host["name"] = entity.get("name")
        host["uuid"] = entity.get("uuid")
        host["mem_capacity_bytes"] = entity.get("memoryCapacityInBytes")
        hosts.append(host)
    
    return hosts

def sort_vm_by_host(api_server,username,passwd,host_uuid_list):
    """
    Fetches the list of VM in the clusters and sort it by HOST.
    Return : Dictionary containing the list of vm details to each host-id
    """
    api_server_endpoint = "/PrismGateway/services/rest/v1/vms"
    url = "https://{}:{}{}".format(
        api_server,
        api_server_port,
        api_server_endpoint
    )
    method = "GET"
  
    resp = process_request(url,method,user=username,password=passwd,headers=headers,exit_on_failure=True)
    entities = resp.json().get("entities")
    vm_list_by_host = {}

    for host_uuid in host_uuid_list:
        #print(host_uuid) #torem
        vm_list =[]
        for entity in entities:
            vm_name = entity.get("vmName")
            vm_uuid = entity.get("uuid")
            vm_mem_cap_bytes = entity.get("memoryCapacityInBytes")
            vm_hostId = entity.get("hostUuid")
            vm_detail = {"vm_name":vm_name, "vm_uuid":vm_uuid, "vm_mem_cap_bytes":vm_mem_cap_bytes}
            if host_uuid == vm_hostId :
                vm_list.append(vm_detail)

        vm_list_by_host[host_uuid] = vm_list
    
    #pprint.pprint(vm_list_by_host) #torem

    return vm_list_by_host

def get_vm_mem_usage(api_server,username,passwd,vm):
    """
    Fetches VM Stats(Memory_usage) by Rest-API call. It includes CVM as well.
    Sampling time : Past One hour
    Sampling rate : Every 5 mins. 
    Total of 13 samples for past one hour and an average usage is calculated.
    """

    #vm_name = vm.get("vm_name")
    vm_uuid = vm.get("vm_uuid")
    vm_mem_cap_bytes = vm.get("vm_mem_cap_bytes")

    api_server_endpoint = "/PrismGateway/services/rest/v1/vms/{}/stats".format(vm_uuid)

    url = "https://{}:{}{}".format(
        api_server,
        api_server_port,
        api_server_endpoint
    )
    method = "GET"
    params = {
        "metrics" : "memory_usage_ppm" ,
        "startTimeInUsecs" : one_hour_before_microseconds,
        "endTimeInUsecs" : now_microseconds,
        "intervalInSecs" : 300
    }

    resp = process_request(url,method,user=username,password=passwd,params=params,headers=headers,exit_on_failure=True)
    for data in resp.json().get("statsSpecificResponses"):
        if data.get("metric") == "memory_usage_ppm":
            values = data.get("values")
            if len(values) > 0 :
                avg_usage_ppm = sum(values) / len(values)
            else: #For some VM is the memory details is not available, assuming it as zero
                avg_usage_ppm = 0

    vm_mem_usage_bytes = vm_mem_cap_bytes * avg_usage_ppm / 1000000
    return vm_mem_usage_bytes

def run_ssh_cmd (pe_ip,username,passwd,cmd):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(pe_ip,port=22,username=username, password=passwd)
        stdin, stdout, stderr = client.exec_command(cmd)
        output = stdout.read().decode().rstrip()
        error = stderr.read().decode()
        client.close() 

        if not error:
            #print("Output ",output)
            return output
        else:
            print("Error ", error)
            exit(1)
    
    except Exception as e:
        print("Couldn't connect to PE Server", e)
        client.close() 
        exit(1)
    
def get_host_ha_reserved_mem(pe_ip,username,passwd,host_uuid):

    cmd = r"links -dump http://0:2030 | grep -i master | awk -F '\\[5\\]' '{print $2}' | awk '{print $1}' | sed 's/.*/http:\/\/&\/sched/'"
    link = run_ssh_cmd(pe_ip=pe_ip,username=username,passwd=passwd,cmd=cmd) 
    cmd = f"links -dump {link} | grep {host_uuid} | head -1 | awk -F '|' '{{print $10}}'"
    ha_reserved_mem = run_ssh_cmd(pe_ip=pe_ip,username=username,passwd=passwd,cmd=cmd) 
    #print("ha_reserved_mem", ha_reserved_mem)
    if ha_reserved_mem.strip().isdigit():
        return int(ha_reserved_mem)*1024*1024
    else :
        return 0

def get_host_mem_usage(api_server,username,passwd,host):
    """
    Calculates the host memory usage by the sum of all individual VM memory usage
    """
    vm_list = host.get("vm_list")

    print("\tFetching Memory usage details of Host:{} ...".format(host.get("name")))
    host_vm_mem_usage_bytes = 0
    for vm in vm_list:
        vm_mem_usage_bytes = get_vm_mem_usage(api_server=api_server,username=username,passwd=passwd,vm=vm )
        host_vm_mem_usage_bytes += vm_mem_usage_bytes
    
    host_ha_reserved_mem_bytes = get_host_ha_reserved_mem(pe_ip=api_server,username=username,passwd=passwd,host_uuid=host.get('uuid'))

    return host_vm_mem_usage_bytes,host_ha_reserved_mem_bytes

def write_to_file(cluster_memory_usage,path,cluster_name):
    """
    Writes the script output to the CSV file 
    """
    if path.endswith("/"):
        path = path[:-1]

    filename = Path(path + "/" +  cluster_name + "_memory_usage_" + now.strftime("%Y-%m-%d-%H_%M") + ".csv")
    try:
        with open(filename, mode='w', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=["Cluster Name", "Host Name", "Memory Capacity(GiB)","VM Memory Consumed(GiB)", "HA Memory Reserved(GiB)","Total Memory Consumed(GiB)", "Memory Consumed %"])
            writer.writeheader()
            writer.writerows(cluster_memory_usage)
        print("Host Memory usage details have been written to '{}'\n".format(filename))  
    except Exception as e :
        print(f"!!! An unexpected error occured : {e}")
        exit(1)

def main():
    parser = argparse.ArgumentParser(description="Get cluster's host memory usage details.")
    parser.add_argument('--pe_ip', required=True, help='PE IP address')
    parser.add_argument('--pe_user', required=True, help='PE Username')
    parser.add_argument('--pe_secret', required=True, help='PE Secret')
    parser.add_argument('--output_path', required=True, help='Path of output file')

    args = parser.parse_args()
    cluster_name = get_cluster_name(api_server=args.pe_ip,username=args.pe_user,passwd=args.pe_secret)
    print("Cluster : {}".format(cluster_name))

    hosts = get_host_details(api_server=args.pe_ip,username=args.pe_user,passwd=args.pe_secret)
    host_uuid_list = []
    for host in hosts:
        host_uuid_list.append(host.get("uuid"))

    vm_list_by_host = sort_vm_by_host(api_server=args.pe_ip,username=args.pe_user,passwd=args.pe_secret,host_uuid_list=host_uuid_list)

    cluster_memory_usage = []
    for host in hosts:
        host["vm_list"] = vm_list_by_host.get(host.get("uuid"))
        host_vm_mem_usage_bytes,host_ha_reserved_mem_bytes = get_host_mem_usage(api_server=args.pe_ip,username=args.pe_user,passwd=args.pe_secret,host=host)
        host["vm_mem_usage_bytes"] = host_vm_mem_usage_bytes
        host["ha_reserved_mem_bytes"] = host_ha_reserved_mem_bytes
        host["mem_usage_bytes"] = host_vm_mem_usage_bytes + host_ha_reserved_mem_bytes
        host["mem_usage_percent"] = host.get("mem_usage_bytes")/host.get("mem_capacity_bytes") * 100 

        cluster_memory_usage.append({
            "Cluster Name": cluster_name,
            "Host Name": host.get("name"),
            "Memory Capacity(GiB)": str(round(host.get("mem_capacity_bytes")/ (1024 ** 3), 2)) + " GiB",
            "VM Memory Consumed(GiB)": str(round(host.get("vm_mem_usage_bytes")/ (1024 ** 3), 2)) + " GiB",
            "HA Memory Reserved(GiB)": str(round(host.get("ha_reserved_mem_bytes")/ (1024 ** 3), 2)) + " GiB",
            "Total Memory Consumed(GiB)": str(round(host.get("mem_usage_bytes")/ (1024 ** 3), 2)) + " GiB",
            "Memory Consumed %" : str(round(host.get("mem_usage_percent"),2)) + "%"
        })

    print(tabulate(cluster_memory_usage, headers="keys", tablefmt="grid"))
    write_to_file(cluster_memory_usage=cluster_memory_usage,path=args.output_path,cluster_name=cluster_name)

if __name__ == "__main__":
    main()
