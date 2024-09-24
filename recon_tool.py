import os
import argparse
import subprocess
import logging
import pandas as pd
import re
import requests
import time
from tabulate import tabulate

# Initialize logger
logging.basicConfig(filename="recon.log", level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Function to validate domain names
def is_valid_domain(domain):
    regex = r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.[A-Za-z]{2,6}$'
    return re.match(regex, domain) is not None

# Regex pattern to match domains
domain_regex = r'(?:(?:\*\.)?([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,}))'

# Check if required tools are installed
def check_tools(tools):
    missing_tools = []
    for tool in tools:
        if subprocess.call(["which", tool], stdout=subprocess.PIPE, stderr=subprocess.PIPE) != 0:
            missing_tools.append(tool)
    return missing_tools

# Create project folder
def create_project_folder(project_name):
    if not os.path.exists(project_name):
        os.makedirs(project_name)
    return project_name

# Load domains from file (CSV or TXT)
def load_domains(file):
    domains = []
    try:
        if file.endswith('.csv'):
            df = pd.read_csv(file)
            for column in df.columns:
                for value in df[column]:
                    if isinstance(value, str):
                        domains.extend(re.findall(domain_regex, value))
        elif file.endswith('.txt'):
            with open(file, 'r') as f:
                text = f.read()
                domains = re.findall(domain_regex, text)
    except FileNotFoundError:
        logging.error(f"File not found: {file}")
        print(f"Error: The file {file} was not found.")
    except pd.errors.EmptyDataError:
        logging.error(f"Empty data in file: {file}")
        print(f"Error: The file {file} is empty.")
    except Exception as e:
        logging.error(f"Error loading domains from file: {e}")
        print(f"An error occurred while loading domains: {e}")
    return domains

# Extract valid domains
def extract_valid_domains(domains):
    valid_domains = [domain for domain in domains if is_valid_domain(domain)]
    return valid_domains

# Find subdomains using Subfinder
def find_subdomains(domain):
    try:
        result = subprocess.run(["subfinder", "-d", domain, "-all"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        subdomains = result.stdout.splitlines()
        return subdomains
    except subprocess.CalledProcessError as e:
        logging.error(f"Error running subfinder for {domain}: {e}")
        return []

# Find subdomains using SecurityTrails API
def find_subdomains_security_trails(domain, api_key):
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    headers = {
        "Content-Type": "application/json",
        "APIKEY": api_key
    }
    
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json().get('subdomains', [])
    else:
        logging.error(f"Error fetching subdomains from SecurityTrails for {domain}: {response.text}")
        return []

# Resolve live subdomains using httpx with -mc 200,301,500
def resolve_live_subdomains(subdomains, project_folder):
    http_200_301_500_subdomains_file = os.path.join(project_folder, "200_301_500.txt")  # Save output to project directory
    try:
        # Write all subdomains to a temporary file for httpx to read
        with open("subdomains.txt", "w") as f:
            for subdomain in subdomains:
                f.write(f"http://{subdomain}\n")  # Prefix with http://

        # Run httpx to check for live subdomains and save output directly to 200_301_500.txt
        result = subprocess.run(["httpx", "-list", "subdomains.txt", "-mc", "200,301,500", "-silent", "-o", http_200_301_500_subdomains_file], 
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Check for errors in the output
        if result.returncode != 0:
            logging.error(f"Error running httpx: {result.stderr}")
            print(f"Error running httpx: {result.stderr}")
            return []

        # Check if the file was created and has content
        if os.path.exists(http_200_301_500_subdomains_file) and os.path.getsize(http_200_301_500_subdomains_file) > 0:
            with open(http_200_301_500_subdomains_file, "r") as f:
                live_subdomains = f.read().splitlines()
            return live_subdomains
        else:
            print(f"{http_200_301_500_subdomains_file} was not created or is empty.")
            return []

    except subprocess.CalledProcessError as e:
        logging.error(f"Error resolving live subdomains: {e}")
        return []

# Run jsfinder on live subdomains
def run_jsfinder(live_subdomains, output_folder):
    # Create a directory to store jsfinder results for each subdomain
    jsfinder_results_folder = os.path.join(output_folder, "jsfinder_results")
    os.makedirs(jsfinder_results_folder, exist_ok=True)

    # Write live subdomains to a temporary file
    temp_jsfinder_input_file = os.path.join(output_folder, "jsfinder_input.txt")
    with open(temp_jsfinder_input_file, "w") as f:
        for subdomain in live_subdomains:
            f.write(f"{subdomain}\n")

    try:
        # Run jsfinder using the temporary input file
        jsfinder_output_file = os.path.join(jsfinder_results_folder, "jsfinder_results.txt")
        process = subprocess.Popen(["jsfinder", "-l", temp_jsfinder_input_file, "-o", jsfinder_output_file], 
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Print the output in real-time
        for line in process.stdout:
            print(line, end='')  # Print to terminal

        # Wait for the process to complete
        process.wait()

        if process.returncode != 0:
            logging.error(f"Error running jsfinder: {process.stderr.read()}")
            print(f"Error running jsfinder: {process.stderr.read()}")
        else:
            print(f"Jsfinder results saved to {jsfinder_output_file}.")

    except Exception as e:
        logging.error(f"Error running jsfinder: {e}")

# Run dirsearch on live subdomains
def run_dirsearch(live_subdomains, output_folder):
    # Create a directory to store dirsearch results for each subdomain
    dirsearch_results_folder = os.path.join(output_folder, "dirsearch_results")
    os.makedirs(dirsearch_results_folder, exist_ok=True)

    # Set to keep track of unique response sizes
    unique_sizes = set()

    for subdomain in live_subdomains:
        dirsearch_output_file = os.path.join(dirsearch_results_folder, f"{subdomain.replace('http://', '').replace('https://', '').replace('/', '_')}_results.txt")
        retries = 0
        max_retries = 3
        backoff_time = 5  # Initial backoff time in seconds

        while retries < max_retries:
            try:
                # Run dirsearch for each subdomain and save the output to a specific file
                with open(dirsearch_output_file, "w") as output_file:
                    process = subprocess.Popen(["dirsearch", "-u", subdomain, "-o", dirsearch_output_file], 
                                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

                    # Print the output in real-time
                    for line in process.stdout:
                        print(line, end='')  # Print to terminal
                        output_file.write(line)  # Write to output file

                    # Wait for the process to complete
                    process.wait()

                    if process.returncode != 0:
                        error_output = process.stderr.read()
                        if "429" in error_output:  # Check for 429 status code in error output
                            print(f"Received 429 Too Many Requests for {subdomain}. Retrying in {backoff_time} seconds...")
                            time.sleep(backoff_time)  # Wait before retrying
                            retries += 1
                            backoff_time *= 2  # Exponential backoff
                            continue  # Retry the same subdomain
                        else:
                            logging.error(f"Error running dirsearch for {subdomain}: {error_output}")
                            print(f"Error running dirsearch for {subdomain}: {error_output}")
                            break  # Exit the loop on other errors
                    else:
                        # Check the size of the output file
                        output_file_size = os.path.getsize(dirsearch_output_file)

                        # Check if the size is unique
                        if output_file_size not in unique_sizes:
                            unique_sizes.add(output_file_size)
                            print(f"Dirsearch results for {subdomain} saved to {dirsearch_output_file}.")
                        else:
                            # If the size is not unique, remove the file
                            os.remove(dirsearch_output_file)
                            print(f"Removed duplicate size result for {subdomain}.")
                        break  # Exit the retry loop on success

            except Exception as e:
                logging.error(f"Error running dirsearch: {e}")
                break  # Exit the loop on exception

        if retries == max_retries:
            print(f"Max retries reached for {subdomain}. Skipping to the next subdomain.")

    return dirsearch_results_folder

# Run Nuclei on live subdomains
def run_nuclei(live_subdomains, output_folder):
    # Create a directory to store Nuclei results for each subdomain
    nuclei_results_folder = os.path.join(output_folder, "nuclei_results")
    os.makedirs(nuclei_results_folder, exist_ok=True)

    for subdomain in live_subdomains:
        nuclei_output_file = os.path.join(nuclei_results_folder, f"{subdomain.replace('http://', '').replace('https://', '').replace('/', '_')}_nuclei_results.txt")
        try:
            # Run Nuclei for each subdomain and save the output to a specific file
            process = subprocess.Popen(["nuclei", "-u", subdomain, "-o", nuclei_output_file], 
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            # Print the output in real-time
            for line in process.stdout:
                print(line, end='')  # Print to terminal

            # Wait for the process to complete
            process.wait()

            if process.returncode != 0:
                logging.error(f"Error running Nuclei for {subdomain}: {process.stderr.read()}")
                print(f"Error running Nuclei for {subdomain}: {process.stderr.read()}")
            else:
                print(f"Nuclei results for {subdomain} saved to {nuclei_output_file}.")

        except Exception as e:
            logging.error(f"Error running Nuclei: {e}")

# Append dirsearch results to 200.txt
def append_dirsearch_results_to_200(dirsearch_output_file, http_200_subdomains_file):
    try:
        with open(dirsearch_output_file, "r") as dirsearch_file:
            dirsearch_results = dirsearch_file.readlines()

        with open(http_200_subdomains_file, "a") as http_200_file:
            http_200_file.write("\n# Dirsearch Results:\n")
            for line in dirsearch_results:
                http_200_file.write(line)

        print(f"Dirsearch results appended to {http_200_subdomains_file}.")
    except Exception as e:
        logging.error(f"Error appending dirsearch results to 200.txt: {e}")

# Generate summary report
def generate_summary_report(domain, live_subdomains):
    report = [
        ["Domain", domain],
        ["Live Subdomains", len(live_subdomains)],
    ]
    print(tabulate(report, headers=["Item", "Details"]))

# Main function to handle the process
def main(args):
    tools = ['subfinder', 'httpx', 'dirsearch', 'nuclei', 'jsfinder', 'python3']
    missing_tools = check_tools(tools)
    if missing_tools:
        print(f"Missing tools: {', '.join(missing_tools)}. Please install them before running the script.")
        return

    project_name = input("Enter the project name: ")
    project_folder = create_project_folder(project_name)

    domains = load_domains(args.file)
    if not domains:
        print("No domains found in the input file.")
        return

    valid_domains = extract_valid_domains(domains)
    if not valid_domains:
        print("No valid domains found.")
        return

    api_key = input("Enter your SecurityTrails API key: ")

    all_subdomains = []  # Temporary list to hold all subdomains

    for domain in valid_domains:
        print(f"Finding subdomains for {domain} using Subfinder...")
        subfinder_subdomains = find_subdomains(domain)
        all_subdomains.extend(subfinder_subdomains)

        print(f"Finding subdomains for {domain} using SecurityTrails...")
        security_trails_subdomains = find_subdomains_security_trails(domain, api_key)
        all_subdomains.extend([f"{sub}.{domain}" for sub in security_trails_subdomains])

    # Remove duplicates
    all_subdomains = list(set(all_subdomains))

    # Save all found subdomains to a file
    subdomains_file = os.path.join(project_folder, "all_subdomains.txt")
    with open(subdomains_file, "w") as f:
        for subdomain in all_subdomains:
            f.write(f"{subdomain}\n")

    print(f"All found subdomains saved to {subdomains_file}.")

    # Print current working directory
    print("Current working directory:", os.getcwd())

    print(f"Resolving live subdomains...")
    live_subdomains = resolve_live_subdomains(all_subdomains, project_folder)

    if live_subdomains:
        print(f"Live subdomains saved to {os.path.join(project_folder, '200_301_500.txt')}.")
        
        # Run jsfinder on live subdomains
        print(f"Running jsfinder on live subdomains...")
        run_jsfinder(live_subdomains, project_folder)

        # Run dirsearch on live subdomains
        print(f"Running dirsearch on live subdomains...")
        dirsearch_results_folder = run_dirsearch(live_subdomains, project_folder)

        print(f"Dirsearch results saved in folder: {dirsearch_results_folder}.")
        
        # Run Nuclei on live subdomains
        print(f"Running Nuclei on live subdomains...")
        run_nuclei(live_subdomains, project_folder)

        # Generate summary report
        generate_summary_report("All Domains", live_subdomains)
    else:
        print("No live subdomains found.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Simple Bug Bounty Recon Tool")
    parser.add_argument("file", type=str, help="Input CSV or TXT file containing domains")
    args = parser.parse_args()
    main(args)
