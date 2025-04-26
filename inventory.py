import requests
import xml.etree.ElementTree as ET
import csv
from getpass import getpass
from urllib.parse import urlencode, quote_plus
import logging
import urllib3
from collections import Counter, defaultdict

# Suppress only the single InsecureRequestWarning from urllib3 needed for this script
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Function to parse XML and extract required data
def parse_xml(xml_data, panorama):
    try:
        root = ET.fromstring(xml_data)
        data = []
        for device in root.findall(".//devices/entry"):
            serial = device.find('serial').text if device.find('serial') is not None else 'N/A'
            hostname = device.find('hostname').text if device.find('hostname') is not None else 'N/A'
            sw_version = device.find('sw-version').text if device.find('sw-version') is not None else 'N/A'
            model = device.find('model').text if device.find('model') is not None else 'N/A'
            data.append([hostname, serial, panorama, sw_version, model])
        return data
    except ET.ParseError as e:
        logging.error(f"Error parsing XML for panorama {panorama}: {e}")
        logging.error(f"XML Data: {xml_data}")
        return []

# Function to make API call and get the XML response
def get_devices_data(panorama_ip, api_key):
    url = f"https://{panorama_ip}/api/?type=op&cmd=<show><devices><all></all></devices></show>"
    headers = {
        'X-PAN-KEY': api_key
    }
    response = requests.get(url, headers=headers, verify=False)
    response.raise_for_status()
    return response.text

# Function to generate API key
def generate_api_key(panorama_ip, username, password):
    params = {
        'type': 'keygen',
        'user': username,
        'password': password
    }
    url = f"https://{panorama_ip}/api/?{urlencode(params, quote_via=quote_plus)}"
    response = requests.get(url, verify=False)
    response.raise_for_status()
    root = ET.fromstring(response.text)
    return root.find(".//key").text

# Main function to iterate over multiple Panoramas and save data to CSV
def main(panorama_ips, username, password, csv_file):
    all_data = []
    for panorama_ip in panorama_ips:
        try:
            logging.info(f"Generating API key for {panorama_ip}")
            api_key = generate_api_key(panorama_ip, username, password)
            logging.info(f"Retrieving device data from {panorama_ip}")
            xml_data = get_devices_data(panorama_ip, api_key)
            panorama_data = parse_xml(xml_data, panorama_ip)
            all_data.extend(panorama_data)
        except requests.RequestException as e:
            logging.error(f"Error retrieving data from {panorama_ip}: {e}")

    # Remove duplicates and sort by software version
    unique_data = {tuple(row): row for row in all_data}.values()
    sorted_data = sorted(unique_data, key=lambda x: x[3])  # Sort by software version

    # Save data to CSV
    with open(csv_file, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['device_name', 'serial', 'panorama', 'sw_version', 'model'])
        writer.writerows(sorted_data)
    logging.info(f"Data saved to {csv_file}")

    # Calculate and print stats for each version
    version_counts = Counter(row[3] for row in sorted_data)
    print("\nVersion Statistics:")
    print(f"{'Version':<15} | {'Device Count':<15}")
    print("-" * 32)
    for version, count in version_counts.items():
        print(f"{version:<15} | {count:<15}")

    # Calculate and print breakdown by model and version
    model_version_counts = defaultdict(lambda: Counter())
    for row in sorted_data:
        model = row[4]
        version = row[3]
        model_version_counts[model][version] += 1

    print("\nVersion Breakdown by Device Model:")
    for model, versions in model_version_counts.items():
        print(f"\nModel: {model}")
        print(f"{'Version':<15} | {'Device Count':<15}")
        print("-" * 32)
        for version, count in versions.items():
            print(f"{version:<15} | {count:<15}")

# Example usage
if __name__ == "__main__":
    panorama_ips = [
        "panorama-1.intranet",
        "panorama-2.intranet"
    ]
    username = input("Enter your username: ")
    password = getpass("Enter your password: ")
    csv_file = 'devices_versions_data.csv'

    main(panorama_ips, username, password, csv_file)
# This script retrieves device information from multiple Panorama devices and saves it to a CSV file.
# It also provides statistics on software versions and a breakdown by device model.