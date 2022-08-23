import os
import requests


def get_tlds(url):
    comments = []
    tlds = []

    response = requests.get(url)
    for line in response.text.splitlines():
        if not line:
            continue
        if line.startswith('#'):
            comments.append(line)
        else:
            tlds.append(line)

    return comments, tlds


def get_special_tlds(url):
    response = requests.get(url)
    # Ignore first line from CSV and return list of domains without the period suffix
    return [line.split(',', 1)[0][:-1].upper() for line in response.text.splitlines()[1:]]


if __name__ == "__main__":
    tlds_url = 'https://data.iana.org/TLD/tlds-alpha-by-domain.txt'
    tlds_location = "../assemblyline/common/net_static.py"
    if not os.path.exists(tlds_location):
        print("Could not find net_static.py file. Make sure you run this script "
              "in its home directory otherwise this won't work.")
        exit(1)

    comments, tlds = get_tlds(tlds_url)
    comments_lines = '\n'.join(comments)
    tlds_lines = '",\n    "'.join(tlds)

    special_tlds_url = "https://www.iana.org/assignments/special-use-domain-names/special-use-domain.csv"
    special_tlds = get_special_tlds(special_tlds_url)
    special_tlds_lines = '",\n    "'.join(special_tlds)

    with open(tlds_location, "w") as tlds_fh:
        tlds_fh.write("# This file is generated using generate_tlds.py script\n"
                      "# DO NOT EDIT! Re-run the script instead...\n\n"
                      f"# Top level domains from: {tlds_url}\n"
                      f"{comments_lines}\n"
                      f"TLDS_ALPHA_BY_DOMAIN = {{\n    \"{tlds_lines}\"\n}}\n\n"
                      f"# Special-use TLDs from: {special_tlds_url}\n"
                      f"TLDS_SPECIAL_BY_DOMAIN = {{\n    \"{special_tlds_lines}\"\n}}")

    print(f"TLDS list file written into: {tlds_location}")
    print("You can now commit the new net_static.py file to your git.")
