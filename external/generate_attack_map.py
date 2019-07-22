import os

CTI_BASE = "/tmp/cti_git"

def clone_cti(base=CTI_BASE):
    import subprocess
    import shutil
    print("Preparing CTI git repo...")

    if os.path.exists(base):
        shutil.rmtree(base)

    subprocess.check_call(["git", "clone", "https://github.com/mitre/cti.git", base])


def get_map(base=CTI_BASE):
    from stix2 import FileSystemSource, CompositeDataSource, Filter

    print("Loading CTI attack-pattern map...")
    enterprise_attack_fs = FileSystemSource(os.path.join(base, "enterprise-attack"))
    mobile_attack_fs = FileSystemSource(os.path.join(base, "mobile-attack"))

    composite_ds = CompositeDataSource()
    composite_ds.add_data_sources([enterprise_attack_fs, mobile_attack_fs])

    filt = Filter('type', '=', 'attack-pattern')

    attack_map = {}
    for item in composite_ds.query(filt):
        name = item['name']

        if item['revoked']:
            print(f"[WARN] Ignored {name.upper()}: This attack-pattern has been revoked.")
            continue

        categories = [x['phase_name'] for x in item['kill_chain_phases']]
        desc = item['description']
        platforms = item['x_mitre_platforms']
        attack_id = None
        for er in item['external_references']:
            if er['source_name'] in ["mitre-attack", "mobile-mitre-attack", "mitre-mobile-attack"]:
                attack_id = er['external_id']
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

if __name__ == "__main__":
    attack_map_location = "../assemblyline/common/attack_map.py"
    if not os.path.exists(attack_map_location):
        print("Could not find attack_map.py file. Make sure you run this script "
              "in its home directory otherwise this won't work.")
        exit(1)

    from pprint import pformat
    clone_cti()
    map = get_map()

    with open(attack_map_location, "w") as attack_map_fh:
        attack_map_fh.write("# This file is generated using generate_attack_map.py script\n"
                            "# DO NOT EDIT! Re-run the script instead...\n\n"
                            f"attack_map = {{\n {pformat(map, width=120)[1:-1]}\n}}")

    print(f"Attack map file written into: {attack_map_location}")
    print("You can now commit the new attack file to your git.")