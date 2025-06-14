import argparse
from pathlib import Path

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


    #Creating the empty Files 
    with open(output_files_name, 'w'):
        pass





if __name__ == "__main__":
    main()