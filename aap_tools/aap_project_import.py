# author: David Weber

import requests
import json
import urllib3
from ansible.parsing.vault import VaultLib, VaultSecret
import getpass
from ansible.errors import AnsibleError
from pprint import pprint

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
aap_host = input("Enter the AAP hostname or IP to import the project to(example: aap_prod.company.com): ")
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


def get_object_id(token, endpoint, object_name):
    HEADERS["Authorization"] = f"Bearer {token}"
    response = requests.get(BASE_URL + endpoint, headers=HEADERS, params={"name": object_name}, verify=False)
    if response.status_code == 200 and response.json()['results']:
        return response.json()['results'][0]['id']


def create_or_skip_credential_type(token, credential_type_data):
    HEADERS["Authorization"] = f"Bearer {token}"
    credential_type_name = credential_type_data['name']
    credential_type_id = get_object_id(token, "credential_types/", credential_type_name)
    
    if credential_type_id:
        print(f"Credential type '{credential_type_name}' already exists with ID: {credential_type_id}")
        return credential_type_id

    response = requests.post(BASE_URL + "credential_types/", headers=HEADERS, json=credential_type_data, verify=False)
    if response.status_code == 201:
        new_credential_type_id = response.json()["id"]
        print(f"Credential type '{credential_type_name}' created with ID: {new_credential_type_id}")
        return new_credential_type_id
    else:
        print(f"Failed to create credential type. Response: {response.text}")
        return None


def create_or_skip_credential(token, credential_data, organization_name):
    HEADERS["Authorization"] = f"Bearer {token}"
    credential_name = credential_data['name']
    credential_id = get_object_id(token, "credentials/", credential_name)
    
    if credential_id:
        print(f"Credential '{credential_name}' already exists with ID: {credential_id}")
        return credential_id

    for key, value in credential_data.get('inputs', {}).items():
        if value == '$encrypted$':
            credential_data['inputs'][key] = 'addsecret'

    credential_type_data = credential_data.get("credential_type")
    if credential_type_data:
        credential_type_id = create_or_skip_credential_type(token, credential_type_data)
        if credential_type_id:
            credential_data['credential_type'] = credential_type_id
        else:
            print(f"Unable to find or create credential type for '{credential_name}'.")
            return None

    organization_id = get_object_id(token, "organizations/", organization_name)
    if organization_id:
        credential_data['organization'] = organization_id
    else:
        print(f"Organization '{organization_name}' not found. Cannot create credential '{credential_name}'.")
        return None

    response = requests.post(BASE_URL + "credentials/", headers=HEADERS, json=credential_data, verify=False)
    if response.status_code == 201:
        new_credential_id = response.json()["id"]
        print(f"Credential '{credential_name}' created with ID: {new_credential_id}")
        return new_credential_id
    else:
        print(f"Failed to create credential. Response: {response.text}")
        return None


def create_or_update_project(token, project_data):
    HEADERS["Authorization"] = f"Bearer {token}"
    project_name = project_data['name']
    project_id = get_object_id(token, "projects/", project_name)
    update = None
    if project_id:
        print(f"\nProject '{project_name}' already exists with ID: {project_id}")
        update = input("Overwrite project? Enter yes or no: ")
        if update == "no":
            print("\n")
            return project_id
    if isinstance(project_data['summary_fields'].get('organization'), dict):
        org_name = project_data['summary_fields']['organization'].get('name', "default")
    org_id = get_object_id(token, "organizations/", org_name)
    project_data['organization'] = org_id
    env_name = "network"
    env_id = get_object_id(token, "execution_environments/", env_name)
    project_data['default_environment'] = env_id
    if isinstance(project_data['summary_fields'].get('credential'), dict):
        scm_credential_name = project_data['summary_fields']['credential']['name']
    scm_credential_id = get_object_id(token, "credentials/", scm_credential_name)
    project_data['credential'] = scm_credential_id
    if update and update == "yes":
        project_data.pop('local_path', None)
        response = requests.patch(BASE_URL + "projects/" + str(project_id) + "/", headers=HEADERS, json=project_data, verify=False)
    else:
        response = requests.post(BASE_URL + "projects/", headers=HEADERS, json=project_data, verify=False)
    if response.status_code in [200, 201]:
        new_project_id = response.json()["id"]
        if update:
            print(f"Project '{project_name}' updated with ID: {new_project_id}")
        else:
            print(f"\nProject '{project_name}' created with ID: {new_project_id}")
        sync_response = requests.post(BASE_URL + f"projects/{new_project_id}/update/", headers=HEADERS, verify=False)
        if sync_response.status_code not in [200, 202]:
            raise ValueError(f"Failed to synchronize project repository. Response: {sync_response.text}\n")
        else:
            print(f"Project '{project_name}' repository synchronized successfully.\n")
        return new_project_id
    else:
        print(f"Failed to create or update project '{project_name}'. Response: {response.text}\n")
        return None


def create_or_update_inventory(token, inventory_data):
    HEADERS["Authorization"] = f"Bearer {token}"
    inventory_name = inventory_data.get('name')
    inventory_id = get_object_id(token, "inventories/", inventory_name)
    update = None
    if inventory_id:
        print(f"Inventory '{inventory_name}' already exists with ID: {inventory_id}")
        update = input("Overwrite inventory? Enter yes or no: ")
        if update == "no":
            print("\n")
            return inventory_id
    if isinstance(inventory_data['summary_fields'].get('organization'), dict):
        org_name = inventory_data['summary_fields']['organization'].get('name', "default")
        inventory_data['organization'] = get_object_id(token, "organizations/", org_name)
    elif 'organization' not in inventory_data['summary_fields'] or not inventory_data['summary_fields']['organization']:
        org_name = "MiND"
        inventory_data['organization'] = get_object_id(token, "organizations/", org_name)
    inventory_data.pop('summary_fields', None)
    if update and update == "yes":
        response = requests.patch(BASE_URL + "inventories/" + str(inventory_id) + "/", headers=HEADERS, json=inventory_data, verify=False)
    else:
        response = requests.post(BASE_URL + "inventories/", headers=HEADERS, json=inventory_data, verify=False)
    if response.status_code in [200, 201]:
        new_inventory_id = response.json()["id"]
        if update:
            print(f"Inventory '{inventory_name}' updated with ID: {new_inventory_id}\n")
        else:
            print(f"Inventory '{inventory_name}' created with ID: {new_inventory_id}\n")
        return new_inventory_id
    else:
        print(f"Failed to create or update inventory '{inventory_name}'. Response: {response.text}\n")
        return None


def create_or_update_inventory_source(token, inventory_id, project_id, inventory_name, source_path):
    HEADERS["Authorization"] = f"Bearer {token}"
    response = requests.get(BASE_URL + "inventory_sources/", headers=HEADERS, params={"inventory": inventory_id, "source_project": project_id}, verify=False)
    update = None
    if response.status_code == 200:
        results = response.json().get('results', [])
        for result in results:
            if result.get('source') == 'scm' and result.get('source_project') == project_id:
                print(f"Inventory source for project ID {project_id} already exists with ID: {result['id']}")
                update = input("Overwrite inventory_source? Enter yes or no: ")
                if update == "no":
                    print("\n")
                    return result['id']
            source_id = result['id']
    source_data = {
        "name": inventory_name + "_inventory_source",
        "source": "scm",
        "source_project": project_id,
        "inventory": inventory_id,
        "source_path": source_path
    }
    if update and update == "yes":
        response = requests.patch(BASE_URL + "inventory_sources/" + str(source_id) + "/", headers=HEADERS, json=source_data, verify=False)
    else:
        response = requests.post(BASE_URL + "inventory_sources/", headers=HEADERS, json=source_data, verify=False)
    if response.status_code in [200, 201]:
        new_source_id = response.json()["id"]
        if update:
            print(f"Inventory source '{source_data['name']}' updated with ID: {new_source_id}\n")
        else:
            print(f"Inventory source '{source_data['name']}' created with ID: {new_source_id}\n")
        update_url = BASE_URL + f"inventory_sources/{new_source_id}/update/"
        response = requests.post(update_url, headers=HEADERS, verify=False)
        if response.status_code in [200, 202]:
            print(f"Inventory source {new_source_id} update initiated successfully.")
        else:
            print(f"Failed to initiate update for inventory source {new_source_id}. Response: {response.text}")
        return new_source_id
    else:
        print(f"Failed to set inventory source '{source_data['name']}'. Response: {response.text}\n")
        return False


def create_or_update_job_template(token, jt_data):
    HEADERS["Authorization"] = f"Bearer {token}"
    job_template_name = jt_data.get('name')
    response = requests.get(BASE_URL + "job_templates/", headers=HEADERS, params={"name": job_template_name}, verify=False)
    update = None
    if response.status_code == 200:
        results = response.json().get('results', [])
        if results:
            existing_jt_id = results[0]['id']
            print(f"Job template '{job_template_name}' already exists with ID: {existing_jt_id}")
            update = input("Overwrite job template? Enter yes or no: ")
            if update == "no":
                print("\n")
                return existing_jt_id

    if isinstance(jt_data['summary_fields'].get('inventory'), dict):
        inventory_name = jt_data['summary_fields']['inventory'].get('name')
        jt_data['inventory'] = get_object_id(token, "inventories/", inventory_name)
    
    if isinstance(jt_data['summary_fields'].get('project'), dict):
        project_name = jt_data['summary_fields']['project'].get('name')
        jt_data['project'] = get_object_id(token, "projects/", project_name)
    
    if isinstance(jt_data['summary_fields'].get('execution_environment'), dict):
        env_name = jt_data['summary_fields']['execution_environment'].get('name')
        jt_data['execution_environment'] = get_object_id(token, "execution_environments/", env_name)

    if update and update == "yes":
        response = requests.patch(BASE_URL + "job_templates/" + str(existing_jt_id) + "/", headers=HEADERS, json=jt_data, verify=False)
    else:
        response = requests.post(BASE_URL + "job_templates/", headers=HEADERS, json=jt_data, verify=False)
    if response.status_code in [200, 201]:
        new_jt_id = response.json()["id"]
        if update:
            print(f"Job template '{jt_data['name']}' updated with ID: {new_jt_id}\n")
        else:
            print(f"Job template '{jt_data['name']}' created with ID: {new_jt_id}\n")
        return new_jt_id
    else:
        print(f"Failed to create job template. Response: {response.text}\n")
        return None


def aap_project_import(token, filename):
    with open(filename, "r") as file:
        data = json.load(file)
    organization_name = data.get("project", {}).get("summary_fields", {}).get("organization", {}).get("name", "Default Organization")

    for credential_data in data.get("credentials", []):
        create_or_skip_credential(token, credential_data, organization_name)

    project_id = create_or_update_project(token, data["project"])
    if not project_id:
        return

    source_path = data["source_path"]
    for inventory_data in data["inventory"]:
        inventory_name = inventory_data["name"]
        inventory_id = create_or_update_inventory(token, inventory_data)
        if not inventory_id:
            continue
        if not create_or_update_inventory_source(token, inventory_id, project_id, inventory_name, source_path):
            continue

    for jt_data in data["job_templates"]:
        if "credentials" in jt_data:
            del jt_data["credentials"]
        create_or_update_job_template(token, jt_data)


if __name__ == "__main__":
    try:
        vault_password = getpass.getpass("Enter Ansible Vault password: ")
        vault_file_path = input("Enter the Ansible Vault filepath/filename(example: vault_file.yml): ")
        token = (decrypt_vault_file(vault_password, vault_file_path)).strip()
        filename = input("Enter the project json filename to be imported: ")
        aap_project_import(token, filename)
    except ValueError as e:
        print(e)