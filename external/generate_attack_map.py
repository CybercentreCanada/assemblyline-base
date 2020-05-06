import shutil
import subprocess
import os

from pprint import pformat

from stix2 import FileSystemSource, CompositeDataSource, Filter
from stix2.utils import get_type_from_id

CTI_BASE = "/tmp/cti_git"


def clone_cti(base=CTI_BASE):
    print("Preparing CTI git repo...")

    if os.path.exists(base):
        shutil.rmtree(base)

    subprocess.check_call(["git", "clone", "https://github.com/mitre/cti.git", base])


def load_datasource(base=CTI_BASE):
    print("Loading CTI datasources map...")
    enterprise_attack_fs = FileSystemSource(os.path.join(base, "enterprise-attack"))
    mobile_attack_fs = FileSystemSource(os.path.join(base, "mobile-attack"))

    composite_ds = CompositeDataSource()
    composite_ds.add_data_sources([enterprise_attack_fs, mobile_attack_fs])
    return composite_ds


def get_attack_map(composite_ds):
    print("Parsing attack patterns ...")
    att_filter = Filter('type', '=', 'attack-pattern')

    attack_map = {}
    for item in composite_ds.query(att_filter):
        name = item['name']

        if item['revoked']:
            print(f"\t[WARN] Ignored {name.upper()}: This attack-pattern has been revoked.")
            continue

        categories = [x['phase_name'] for x in item['kill_chain_phases']]
        desc = item['description']
        platforms = item['x_mitre_platforms']
        attack_id = None
        for er in item['external_references']:
            if er['source_name'] in ["mitre-attack", "mobile-mitre-attack", "mitre-mobile-attack"]:
                attack_id = er['external_id']
                break

        if attack_id:
            attack_map[attack_id] = {
                "name": name,
                "categories": categories,
                "description": desc,
                "platforms": platforms,
                "attack_id": attack_id
            }
            print(f"\tAdding {name.upper()} as ID: {attack_id}")
        else:
            print(f"[ERR] Ignored {name.upper()}: No attack ID found.")

    return attack_map


def get_software_map(composite_ds):
    print("Parsing softwares ...")
    malware_filter = Filter('type', '=', 'malware')
    tool_filter = Filter('type', '=', 'tool')

    software_map = {}
    for cur_filter in [malware_filter, tool_filter]:
        for item in composite_ds.query(cur_filter):
            name = item['name']
            if cur_filter == malware_filter:
                soft_type = 'malware'
            else:
                soft_type = 'tool'

            if item['revoked']:
                print(f"\t[WARN] Ignored {name.upper()}: This malware has been revoked.")
                continue

            desc = item['description']
            platforms = item.get('x_mitre_platforms') or []
            software_id = None
            for er in item['external_references']:
                if er['source_name'] in ["mitre-attack", "mobile-mitre-attack", "mitre-mobile-attack"]:
                    software_id = er['external_id']
                    break

            related_attack_ids = []
            attack_pattern_refs = [r.target_ref
                                   for r in composite_ds.relationships(item, 'uses', source_only=True)
                                   if get_type_from_id(r.target_ref) == 'attack-pattern']
            for attack_item in composite_ds.query([Filter('type', '=', 'attack-pattern'),
                                                   Filter('id', 'in', attack_pattern_refs)]):
                for er in attack_item['external_references']:
                    if er['source_name'] in ["mitre-attack", "mobile-mitre-attack", "mitre-mobile-attack"]:
                        related_attack_ids.append(er['external_id'])
                        break

            if software_id:
                software_map[software_id] = {
                    "name": name,
                    "description": desc,
                    "platforms": platforms,
                    "software_id": software_id,
                    "type": soft_type,
                    "attack_ids": related_attack_ids
                }
                print(f"\tAdding {name.upper()} as ID: {software_id}")
            else:
                print(f"[ERR] Ignored {name.upper()}: No attack ID found.")

    return software_map


if __name__ == "__main__":
    attack_map_location = "../assemblyline/common/attack_map.py"
    if not os.path.exists(attack_map_location):
        print("Could not find attack_map.py file. Make sure you run this script "
              "in its home directory otherwise this won't work.")
        exit(1)

    clone_cti()
    datasource = load_datasource()
    att_map = get_attack_map(datasource)
    soft_map = get_software_map(datasource)

    with open(attack_map_location, "w") as attack_map_fh:
        attack_map_fh.write("# This file is generated using generate_attack_map.py script\n"
                            "# DO NOT EDIT! Re-run the script instead...\n\n"
                            f"attack_map = {{\n {pformat(att_map, width=120)[1:-1]}\n}}\n\n"
                            f"software_map = {{\n {pformat(soft_map, width=120)[1:-1]}\n}}\n")

    print(f"Attack map file written into: {attack_map_location}")
    print("You can now commit the new attack file to your git.")
