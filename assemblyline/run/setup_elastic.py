import json
import os
import random
import requests
import string
import time

from requests.exceptions import ConnectionError

class SetupException(Exception):
    pass


def set_password(user, password):
    try:
        print(f"\nSetting up {user} password...")
        req = requests.post(f"http://elastic:{ELASTIC_PASSWORD}@{ELASTIC_HOST}:9200/_security/user/{user}/_password",
                            headers={"Content-Type": "application/json"},
                            data=json.dumps({"password": password}))
        if not req.ok:
            raise SetupException(f"ERROR: Failed to set password for user: {user}")

        print("Password set")
    except SetupException as e:
        print(str(e))


def create_role(name, cluster_priv=None, indices=None):
    try:
        print(f"\nCreating role {name}...")

        if cluster_priv is None:
            cluster_priv = []

        if indices is None:
            indices = []

        role = {"cluster": cluster_priv,
                "indices": [
                    {"names": indices,
                     "privileges": ["all"],
                     "allow_restricted_indices": False}],
                "applications": [],
                "run_as": [],
                "metadata": {}}
        req = requests.post(f"http://elastic:{ELASTIC_PASSWORD}@{ELASTIC_HOST}:9200/_security/role/{name}",
                            headers={"Content-Type": "application/json"},
                            data=json.dumps(role))

        if not req.ok:
            raise SetupException(f"ERROR: Failed to create role: {name}")

        print("Role created")
    except SetupException as e:
        print(str(e))


def create_user(name, password, roles):
    try:
        print(f"\nCreating user {name}...")

        user = {"password": password,
                "roles": roles,
                "full_name": None,
                "email": None,
                "metadata": {}}

        req = requests.post(f"http://elastic:{ELASTIC_PASSWORD}@{ELASTIC_HOST}:9200/_security/user/{name}",
                            headers={"Content-Type": "application/json"},
                            data=json.dumps(user))
        if not req.ok:
            raise SetupException(f"ERROR: Failed to create user: {name}")

        print("User created")
    except SetupException as e:
        print(str(e))


def create_ilm_policy(name, rollover_age=None, rollover_size=None, rollover_doc_count=None,
                      warm_readonly=True, warm_age=None, delete_age=None):
    try:
        print(f"\nCreating ILM policy {name}...")

        data_base = {
            "policy": {
                "phases": {
                    "hot": {
                        "min_age": "0ms",
                        "actions": {
                            "set_priority": {
                                "priority": 100
                            }
                        }
                    },
                    "warm": {
                        "actions": {
                            "set_priority": {
                                "priority": 50
                            }
                        }
                    }
                }
            }
        }

        rollover_data = {}
        delete_data = {}

        if rollover_age:
            rollover_data['max_age'] = rollover_age
        if rollover_size:
            rollover_data['max_size'] = rollover_size
        if rollover_doc_count:
            rollover_data['max_docs'] = rollover_doc_count

        if delete_age:
            delete_data = {
                "min_age": delete_age,
                "actions": {
                    "delete": {}
                }
            }

        if rollover_data:
            data_base['policy']['phases']['hot']['actions']['rollover'] = rollover_data

        if delete_data:
            data_base['policy']['phases']['delete'] = delete_data

        if warm_readonly:
            data_base['policy']['phases']['warm']['actions']['readonly'] = {}

        if warm_age:
            data_base['policy']['phases']['warm']['min_age'] = warm_age

        pol_req = requests.put(f"http://elastic:{ELASTIC_PASSWORD}@{ELASTIC_HOST}:9200/_ilm/policy/{name}",
                               headers={"Content-Type": "application/json"},
                               data=json.dumps(data_base))
        if not pol_req.ok:
            raise SetupException(f"ERROR: Failed to create ILM policy: {name}")

        print("Policy created")
    except SetupException as e:
        print(str(e))


if __name__ == "__main__":
    ELASTIC_HOST = os.getenv("ELASTIC_HOST")
    ELASTIC_PASSWORD = os.getenv("ELASTIC_PASSWORD")
    APM_DELETE_AFTER = os.getenv("APM_DELETE_AFTER", "4d")
    FILEBEAT_DELETE_AFTER = os.getenv("FILEBEAT_DELETE_AFTER", "3d")
    METRICBEAT_DELETE_AFTER = os.getenv("METRICBEAT_DELETE_AFTER", "4d")

    # Testing connection to elasticsearch
    elastic_up = False
    while not elastic_up:
        try:
            req = requests.get(f"http://elastic:{ELASTIC_PASSWORD}@{ELASTIC_HOST}:9200/_cluster/health")
            if req.status_code == 401:
                print(f"Cannot configure elasticsearch server at {ELASTIC_HOST} with the provided password. Exiting...")
                if os.getenv("SU_USERNAME") and os.getenv("SU_PASSWORD"):
                    req = requests.get(f"http://{os.getenv('SU_USERNAME')}:{os.getenv('SU_PASSWORD')}"
                                       f"@{ELASTIC_HOST}:9200/_cluster/health")
                    if req.status_code == 401:
                        exit(1)
                exit(0)

            elastic_up = True
            print('Server is now online!')
        except ConnectionError:
            print(f"Waiting for elasticsearch server [{ELASTIC_HOST}] to come online...")
            time.sleep(1)

    # Setup APM ILM policies
    create_ilm_policy("apm-7.5.0-error", rollover_age="1d", rollover_size="5gb",
                      warm_readonly=True, delete_age=APM_DELETE_AFTER)
    create_ilm_policy("apm-7.5.0-metric", rollover_age="1d", rollover_size="5gb",
                      warm_readonly=True, delete_age=APM_DELETE_AFTER)
    create_ilm_policy("apm-7.5.0-span", rollover_age="1d", rollover_size="5gb",
                      warm_readonly=True, delete_age=APM_DELETE_AFTER)
    create_ilm_policy("apm-7.5.0-transaction", rollover_age="1d", rollover_size="5gb",
                      warm_readonly=True, delete_age=APM_DELETE_AFTER)

    # Setup filebeat ILM policies
    create_ilm_policy("filebeat-7.5.0", rollover_age="1d", rollover_size="20gb",
                      warm_readonly=True, delete_age=FILEBEAT_DELETE_AFTER)

    # Setup metricbeat ILM policies
    create_ilm_policy("metricbeat-7.5.0", rollover_age="1d", rollover_size="5gb",
                      warm_readonly=True, delete_age=METRICBEAT_DELETE_AFTER)

    # Creating kibana user
    if os.getenv("KIBANA_PASSWORD"):
        set_password("kibana", os.getenv("KIBANA_PASSWORD"))

    # Creating apm user
    if os.getenv("APM_PASSWORD"):
        create_role('apm', cluster_priv=["manage_ilm", "manage_pipeline"], indices=["apm-*", ".ml-anomalies*"])
        create_user('apm', os.getenv("APM_PASSWORD"), ["apm_user", "apm_system", "kibana_system", "apm"])

    # Creating filebeat user
    if os.getenv("FILEBEAT_PASSWORD"):
        create_role('filebeat', cluster_priv=["manage_ilm", "manage_pipeline"], indices=["filebeat-*"])
        create_user('filebeat', os.getenv("FILEBEAT_PASSWORD"), ["beats_system", "kibana_system", "filebeat"])

    # Creating metricbeat user
    if os.getenv("METRICBEAT_PASSWORD"):
        create_user('metricbeat', os.getenv("METRICBEAT_PASSWORD"), ["superuser"])

    # Creating assemblyline user
    if os.getenv("AL_PASSWORD"):
        create_role('assemblyline_system',
                    cluster_priv=["manage_index_templates", "manage_ilm"],
                    indices=[
                        "al_metrics_*",
                        "alert*",
                        "cached_*",
                        "emptyresult*",
                        "error*",
                        "file*",
                        "heuristic*",
                        "result*",
                        "service*",
                        "signature*",
                        "submission*",
                        "user*",
                        "vm*",
                        "workflow*"])
        create_user('assemblyline', os.getenv("AL_PASSWORD"), ["assemblyline_system"])

    # Creating new super user
    if os.getenv("SU_USERNAME"):
        if os.getenv("SU_PASSWORD"):
            create_user(os.getenv("SU_USERNAME"), os.getenv("SU_PASSWORD"), ["superuser"])

    # Creating Kibana only user
    if os.getenv("K_USERNAME"):
        if os.getenv("K_PASSWORD"):
            create_user(os.getenv("K_USERNAME"),
                        os.getenv("K_PASSWORD"),
                        ["kibana_user","apm_user","monitoring_user"])

    # Disable temporary password by setting a random one
    char_space = string.ascii_uppercase + string.digits + string.ascii_lowercase
    password = ''.join(random.SystemRandom().choice(char_space) for _ in range(32))
    set_password('elastic', password)
