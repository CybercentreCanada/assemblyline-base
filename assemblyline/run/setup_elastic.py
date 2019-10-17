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
    print(f"\nSetting up {user} password...")
    req = requests.post(f"http://elastic:{ELASTIC_PASSWORD}@{ELASTIC_HOST}:9200/_security/user/{user}/_password",
                        headers={"Content-Type": "application/json"},
                        data=json.dumps({"password": password}))
    if not req.ok:
        raise SetupException(f"ERROR: Failed to set password for user: {user}")

    print("Password set")


def create_role(name, cluster_priv=None, indices=None):
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


def create_user(name, password, roles):
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


if __name__ == "__main__":
    ELASTIC_HOST = os.getenv("ELASTIC_HOST")
    ELASTIC_PASSWORD = os.getenv("ELASTIC_PASSWORD")

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

    # Creating kibana user
    if os.getenv("KIBANA_PASSWORD"):
        try:
            set_password("kibana", os.getenv("KIBANA_PASSWORD"))
        except SetupException as e:
            print(str(e))

    # Creating apm user
    if os.getenv("APM_PASSWORD"):
        try:
            create_role('apm', cluster_priv=["manage_ilm", "manage_pipeline"], indices=["apm-*", ".ml-anomalies*"])
            create_user('apm', os.getenv("APM_PASSWORD"), ["apm_user", "apm_system", "kibana_system", "apm"])
        except SetupException as e:
            print(str(e))

    # Creating filebeat user
    if os.getenv("FILEBEAT_PASSWORD"):
        try:
            create_role('filebeat', cluster_priv=["manage_ilm", "manage_pipeline"], indices=["filebeat-*"])
            create_user('filebeat', os.getenv("FILEBEAT_PASSWORD"), ["beats_system", "kibana_system", "filebeat"])
        except SetupException as e:
            print(str(e))

    # Creating metricbeat user
    if os.getenv("METRICBEAT_PASSWORD"):
        try:
            create_user('metricbeat', os.getenv("METRICBEAT_PASSWORD"), ["superuser"])
        except SetupException as e:
            print(str(e))

    # Creating assemblyline user
    if os.getenv("AL_PASSWORD"):
        try:
            create_role('assemblyline_system', 
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
        except SetupException as e:
            print(str(e))

    # Creating new super user
    if os.getenv("SU_USERNAME"):
        if os.getenv("SU_PASSWORD"):
            try:
                create_user(os.getenv("SU_USERNAME"), os.getenv("SU_PASSWORD"), ["superuser"])
            except SetupException as e:
                print(str(e))

    # Creating Kibana only user
    if os.getenv("K_USERNAME"):
        if os.getenv("K_PASSWORD"):
            try:
                create_user(os.getenv("K_USERNAME"),
                            os.getenv("K_PASSWORD"),
                            ["kibana_user","apm_user","monitoring_user"])
            except SetupException as e:
                print(str(e))

    # Disable temporary password by setting a random one
    try:
        char_space = string.ascii_uppercase + string.digits + string.ascii_lowercase
        password = ''.join(random.SystemRandom().choice(char_space) for _ in range(32))
        set_password('elastic', password)
    except SetupException as e:
        print(str(e))