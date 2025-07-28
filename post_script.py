import argparse
import datetime
from pathlib import Path

current_time = datetime.datetime.now(datetime.timezone.utc)  # Use timezone-aware UTC datetime

def main():
    # Parse command line arguments
    # Example usage: python script.py --pc_ip <ip> --username <username> --cluster_name <cluster_name>
    parser = argparse.ArgumentParser(description="Calculate VM allocation per TShirt size.")
    parser.add_argument('--output_path', required=True, help='Path of output file')
    parser.add_argument('--output_files_name', required=True, help='File to copy the output filenames')

    args = parser.parse_args()
    if not args.output_path or not args.output_files_name:
        parser.error("output_path and output_files must be provided.")

    output_path = args.output_path   
    # output_file = args.output_files_name
    if output_path.endswith("/"):
        args.output_files = output_path[:-1]
    
    output_files_name = Path(output_path + "/" +args.output_files_name)

    filetypes = ["vm_inventory","host_inventory","resources","vm_disk","cluster_health","vm_network","host_network"]
    with open(output_files_name, 'r') as f:
            content = [line.strip() for line in f]
    
    filenames = {}

    for filetype in filetypes:
        filenames[filetype] = []

    for filename in content:
        #print(filename)
        for filetype in filetypes:
            if filetype in filename:
                filenames[filetype].append(filename) 
        
    #print(filenames)

    for filetype,file_list in filenames.items():
        if file_list:
            output_fname = Path(output_path + "/ALL_PC_" + filetype  + "_"+ current_time.strftime("%Y-%m-%d-%H-%M-%S") + ".csv")
            with open(output_fname, 'w') as outfile:
                firstfile = True 
                for fname in file_list:
                    with open(fname, 'r') as infile:
                        if firstfile:
                            firstfile = False
                        else:
                            next(infile)
                        for line in infile:
                            outfile.write(line)           
            print("The consolidated reports of all PC are available in '{}'".format(output_fname))



if __name__ == "__main__":
    main()