import requests
import csv
from azure.identity import ClientSecretCredential

client_id = "<your_client_id>"
client_secret = "<your_client_secret>"
tenant_id = "<your_tenant_id>"
reference_name_purview = "<your_purview_account_name>"
purview_endpoint = f"https://{reference_name_purview}.purview.azure.com"

# Define the connectedVia reference name to search for
connectedVia_referenceName = "<your_ir_name>"
output_read_file = "scans_ir_read.csv"
output_deleted_file = "scans_ir_deleted.csv"
api_version = "2022-07-01-preview"

def get_credentials():
  credentials = ClientSecretCredential(client_id=client_id, client_secret=client_secret, tenant_id=tenant_id)
  access_token = credentials.get_token("https://purview.azure.net/.default").token
  return access_token

# Define the function to get the headers with the authorization token
def get_headers():
    # Get the access token
    access_token = get_credentials()

    # Define the headers with the authorization token
    headers = {
        "Content-Type": "application/json",
        "Accept": f"application/json;api-version={api_version}",
        "Authorization": f"Bearer {access_token}"
    }

    return headers

# Define the function to get all scans that have a specific connectedVia.referenceName
def get_scans():

  try:
    headers = get_headers()
    # print(headers)

    # Get all data sources
    datasources_url = f"{purview_endpoint}/scan/datasources?api-version={api_version}"
    datasources_response = requests.get(datasources_url, headers=headers)
    datasources = datasources_response.json()["value"]
  except requests.exceptions.HTTPError as error:
    if error.response.status_code == 401:
      print("Authentication failed. Please check your credentials.")
    else:
      print(f"HTTP error occurred: {error}")
    return None
  
  # Loop through each data source and get its scans
  scans = []
  print(f'Found scan with IR {connectedVia_referenceName}:')
  for datasource in datasources:
    datasource_name = datasource["name"]
    scans_url = f"{purview_endpoint}/scan/datasources/{datasource_name}/scans?api-version={api_version}"
    # print(scans_url)
    scans_response = requests.get(scans_url, headers=headers)
    # print(scans_response.json())
    scans_data = scans_response.json()["value"]

    # Loop through each scan and check for connectedVia.referenceName
    for scan in scans_data:
      if "connectedVia" in scan["properties"] and scan["properties"]["connectedVia"] and scan["properties"]["connectedVia"]["referenceName"] == connectedVia_referenceName:
        scan_name = scan["name"]
        scan_id = scan["id"]
        scans.append({
            "dataSourceName": datasource_name,
            "scanName": scan_name,
            "scanId": scan_id,
            "url": f'https://web.purview.azure.com/resource/purviewdemoaccount/main/datasource/registeredSources/source?dataSourceId=datasources%2F{datasource_name}&section=scans'
        })
        print(f'{scan_name} in data source {datasource_name}')

  # Export the scans to a CSV file
  with open(output_read_file, "w", newline="") as csvfile:
    fieldnames = ["dataSourceName", "scanName", "scanId", "url"]
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    for scan in scans:
      writer.writerow(scan)

  return scans

# Define the function to delete all scans that have a specific connectedVia.referenceName
def delete_scans():
  headers = get_headers()

  # Get all scans that have a specific connectedVia.referenceName
  # OPTION 1: If you are sure about what to delete, uncomment below line and comment out OPTION 2
  # scans = get_scans()
  # END OPTION 1

  # Load csv in output_file and read columns header to a dict so that we can access scan["dataSourceName"] and scan["scanName"]. 
  # OPTION 2: This option will only delete scans in the .csv file
  scans = []
  with open(output_read_file, "r") as csvfile:
    reader = csv.DictReader(csvfile)
    for scan in reader:
      scans.append(scan)
  # END OPTION 2

  # Loop through each scan and delete it
  deleted_scans = []
  for scan in scans:
    datasource_name = scan["dataSourceName"]
    scan_name = scan["scanName"]
    scan_id = scan["scanId"]
    delete_url = f"{purview_endpoint}/scan/datasources/{datasource_name}/scans/{scan_name}?api-version={api_version}"
    print(f'Deleting URL: {delete_url}')
    delete_response = requests.delete(delete_url, headers=headers)
    if delete_response.status_code == 204 or delete_response.status_code == 200:
      deleted_scans.append(scan)

  # Export the deleted scans to a CSV file
  with open(output_deleted_file, "w", newline="") as csvfile:
    fieldnames = ["dataSourceName", "scanName", "scanId", "url"]
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    for scan in deleted_scans:
      writer.writerow(scan)

  return deleted_scans


if __name__ == "__main__":

  # STEP 1: Get all scans that have a specific IR name
  get_scans()

  # STEP 2: Open scans_ir_read.csv and review the scans to be deleted. Delete any line that you don't want the delete script to delete the scans.

  # STEP 3: This will delete all scans that have a specific IR name.
  # a. Comment out get_scans() 
  # b. Uncomment delete_scans()
  # delete_scans()