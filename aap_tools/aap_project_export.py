# author: David Weber

import requests
import json
import urllib3
from pprint import pprint
from ansible.parsing.vault import VaultLib, VaultSecret
import getpass
from ansible.parsing.vault import VaultLib, VaultSecret
from ansible.errors import AnsibleError, AnsibleParserError
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

aap_host = input("Enter the AAP hostname or IP to export the project from(example: aap_dev.company.com): ")
BASE_URL = f"https://{aap_host}/api/v2/"
HEADERS = {
    "Content-Type": "application/json",
    "Authorization": None
}

def decrypt_vault_file(vault_password, vault_file_path):
    with open(vault_file_path, 'rb') as f:
        b_vault_data = f.read()
    secret = VaultSecret(vault_password.encode('utf-8'))
    vault = VaultLib(secrets=[('default', secret)])
    try:
        decrypted_data = vault.decrypt(b_vault_data)
    except AnsibleError as e:
        raise AnsibleError(f"Error decrypting vault file: {e}")

    return decrypted_data.decode('utf-8')

def get_project_id(token, project_name):
    HEADERS["Authorization"] = f"Bearer {token}"
    response = requests.get(BASE_URL + "projects/", headers=HEADERS, params={"name": project_name}, verify=False)
    data = response.json()
    if data["count"] == 1:
        return data["results"][0]["id"]
    else:
        print(f"Project {project_name} not found or multiple projects with the same name.")
        return None

def aap_project_export(token):
    project_name = input("Enter the project name: ")
    project_id = get_project_id(token, project_name)

    if not project_id:
        return

    # Fetch project details
    project_response = requests.get(BASE_URL + f"projects/{project_id}/", headers=HEADERS, verify=False)
    project_data = project_response.json()

    # Fetch related job templates
    job_templates_response = requests.get(BASE_URL + "job_templates/", headers=HEADERS, params={"project__id": project_id}, verify=False)
    job_templates_data = job_templates_response.json()

    # Fetch related execution environments, credentials, and credential types
    execution_environments = []
    credentials = []
    inventories = []
    inventory_sources = []
    for jt in job_templates_data["results"]:
        if jt["execution_environment"]:
            ee_id = jt["execution_environment"]
            ee_response = requests.get(BASE_URL + f"execution_environments/{ee_id}/", headers=HEADERS, verify=False)
            if ee_response.json() not in execution_environments:
                execution_environments.append(ee_response.json())
        if jt["inventory"]:
            inventory_id = jt["inventory"]
            inventory_response = requests.get(BASE_URL + f"inventories/{inventory_id}/", headers=HEADERS, verify=False)
            if inventory_response.json() not in inventories:
                inventories.append(inventory_response.json())
                inventory_source_response = requests.get(BASE_URL + f"inventories/{inventory_id}/inventory_sources/", headers=HEADERS, verify=False)
                inventory_sources.append(inventory_source_response.json()["results"][0]["source_path"])
        for cred in jt["summary_fields"]["credentials"]:
            cred_id = cred["id"]
            cred_response = requests.get(BASE_URL + f"credentials/{cred_id}/", headers=HEADERS, verify=False)
            cred_data = cred_response.json()
            cred_type_url = BASE_URL + f"credential_types/{cred_data['credential_type']}/"
            cred_type_response = requests.get(cred_type_url, headers=HEADERS, verify=False)
            cred_type_data = cred_type_response.json()
            credential = {
                "name": cred_data["name"],
                "credential_type": cred_type_data,
                "inputs": {k: v for k, v in cred_data["inputs"].items() if k != "password"}  # Exclude secrets
            }
            if credential not in credentials:
                credentials.append(credential)

    source_path = inventory_sources[0]

    # Compile all data
    export_data = {
        "project": project_data,
        "inventory": inventories,
        "source_path": source_path,
        "job_templates": job_templates_data["results"],
        "execution_environments": execution_environments,
        "credentials": credentials
    }

    # Save to a JSON file
    with open(f"{project_name}.json", "w") as file:
        json.dump(export_data, file, indent=4)
    return project_name

if __name__ == "__main__":
    vault_file_path = input("Enter the Ansible Vault filepath/filename(example: vault_file.yml): ")
    vault_password = getpass.getpass("Enter Ansible Vault password: ")
    token = (decrypt_vault_file(vault_password, vault_file_path)).strip()
    project_name = aap_project_export(token)
    print(f"project {project_name} successfully exported to {project_name}.json")

